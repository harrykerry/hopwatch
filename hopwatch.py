#!/usr/bin/env python3
"""
hopwatch - lightweight local internet performance & usage monitor.

Stdlib only. Samples packet loss / latency / jitter per network hop, measures
throughput periodically, tracks interface byte counters for usage, records
degradation incidents, and serves a local dashboard.

    python3 hopwatch.py              # collect + serve dashboard
    python3 hopwatch.py --once       # take a single sample and exit
    python3 hopwatch.py --serve-only # serve existing data, don't collect
    python3 hopwatch.py --report     # print an ISP-ready evidence report
"""

import argparse
import json
import os
import re
import socketserver
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
SAMPLES = os.path.join(DATA, "samples.jsonl")
INCIDENTS = os.path.join(DATA, "incidents.jsonl")
NETWORKS = os.path.join(DATA, "networks.json")
DESTS = os.path.join(DATA, "destinations.json")
DEVICES = os.path.join(DATA, "devices.json")
HOSTS = os.path.join(DATA, "hosts.json")
APPS = os.path.join(DATA, "apps.json")
ISPHOP = os.path.join(DATA, "isp_hop.json")
CONF_PATH = os.path.join(BASE, "hopwatch.conf.json")

DEFAULT_CONF = {
    "interface": "auto",
    "port": 8765,
    "sample_interval_sec": 60,
    "ping_count": 10,
    "ping_spacing_sec": 0.2,
    "speedtest_interval_sec": 1800,
    "speedtest_bytes": 1500000,
    "loss_warn_pct": 3.0,
    "loss_crit_pct": 8.0,
    "plan_down_mbps": 15.0,
    "fup_cap_gb": 500,
    "cycle_start_day": 1,
    "retain_days": 90,
    "targets": [
        {"key": "lan",   "label": "Your router",   "host": "auto",            "scope": "Home network"},
        {"key": "isp",   "label": "ISP border",    "host": "auto-isp",        "scope": "first public hop"},
        {"key": "intl",  "label": "International", "host": "1.1.1.1",         "scope": "outside your country"},
        {"key": "cache", "label": "In-country",    "host": "auto-cache",      "scope": "ISP-cached service"},
    ],
    "speedtests": [
        {"key": "intl",  "label": "International",
         "url": "https://proof.ovh.net/files/100Mb.dat"},
        {"key": "cache", "label": "In-country",
         "url": "https://dl.google.com/chrome/mac/universal/stable/GGRO/googlechrome.dmg"},
    ],
}


# ----------------------------------------------------------------- config ----

def load_conf():
    conf = dict(DEFAULT_CONF)
    if os.path.exists(CONF_PATH):
        try:
            with open(CONF_PATH) as fh:
                conf.update(json.load(fh))
        except Exception as exc:
            print(f"[hopwatch] bad config, using defaults: {exc}", file=sys.stderr)
    if conf.get("interface") == "auto":
        conf["interface"] = detect_interface() or "en0"
    gw = detect_gateway()
    for t in conf["targets"]:
        if t.get("host") == "auto":
            # the LAN target is the default gateway
            t["host"] = gw or "192.168.1.1"
        elif t.get("host") == "auto-isp":
            t["host"] = detect_isp_hop() or (gw or "192.168.1.1")
        elif t.get("host") == "auto-cache":
            ip = run(["/usr/bin/dig", "+short", "+time=3", "www.google.com"],
                     timeout=8)
            ips = [x.strip() for x in ip.splitlines()
                   if re.match(r"^\d+\.\d+\.\d+\.\d+$", x.strip())]
            t["host"] = ips[0] if ips else "8.8.8.8"
    return conf


def write_default_conf():
    if not os.path.exists(CONF_PATH):
        with open(CONF_PATH, "w") as fh:
            json.dump(DEFAULT_CONF, fh, indent=2)
            fh.write("\n")


def run(cmd, timeout=30):
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.stdout
    except Exception:
        return ""


def detect_gateway():
    out = run(["/sbin/route", "-n", "get", "default"], timeout=5)
    m = re.search(r"gateway:\s*([0-9.]+)", out)
    return m.group(1) if m else None


def detect_interface():
    out = run(["/sbin/route", "-n", "get", "default"], timeout=5)
    m = re.search(r"interface:\s*(\S+)", out)
    return m.group(1) if m else None


def hardware_ports():
    """Map interface -> hardware port name (Wi-Fi, iPhone USB, Ethernet...)."""
    out = run(["/usr/sbin/networksetup", "-listnetworkserviceorder"], timeout=10)
    ports = {}
    for m in re.finditer(r"\(Hardware Port: ([^,]+), Device: ([^)]+)\)", out):
        ports[m.group(2).strip()] = m.group(1).strip()
    return ports


def wifi_info(iface):
    """(ssid, bssid) for a Wi-Fi interface, or (None, None)."""
    out = run(["/usr/sbin/ipconfig", "getsummary", iface], timeout=8)
    ssid = bssid = None
    for line in out.splitlines():
        t = line.strip()
        if t.startswith("SSID :"):
            ssid = t.split(":", 1)[1].strip() or None
        elif t.startswith("BSSID :"):
            bssid = t.split(":", 1)[1].strip() or None
    return ssid, bssid


def gateway_mac(gw):
    """Gateway MAC - a permission-free fingerprint for the network.

    The ARP entry may be absent if nothing has talked to the gateway recently,
    so nudge it with a single ping and re-read before giving up.
    """
    if not gw:
        return None

    def lookup():
        out = run(["/usr/sbin/arp", "-an"], timeout=5)
        for line in out.splitlines():
            if "(" + gw + ")" in line:
                m = re.search(r"at ([0-9a-fA-F:]{11,17})", line)
                if m and "incomplete" not in line:
                    return m.group(1).lower()
        return None

    mac = lookup()
    if mac:
        return mac
    run(["/sbin/ping", "-c", "1", "-W", "800", "-q", gw], timeout=5)
    return lookup()


def _is_private(ip):
    try:
        a, b = (int(x) for x in ip.split(".")[:2])
    except ValueError:
        return True
    return (a == 10 or a == 127 or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168) or (a == 100 and 64 <= b <= 127)
            or a == 169)


def detect_isp_hop(probe="1.1.1.1"):
    """First public hop on the path out - effectively the ISP's edge.

    Loss that starts here while the gateway stays clean is upstream of the
    subscriber line. Cached, because traceroute is slow.
    """
    cached = _json_read(ISPHOP, {})
    if cached.get("ip") and (time.time() - cached.get("ts", 0)) < 7 * 86400:
        return cached["ip"]
    out = run(["/usr/sbin/traceroute", "-n", "-w", "1", "-q", "1", "-m", "12",
               probe], timeout=60)
    for line in out.splitlines():
        for tok in line.split():
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", tok) and not _is_private(tok):
                _json_write(ISPHOP, {"ip": tok, "ts": time.time()})
                return tok
    return None


def self_ip():
    iface = detect_interface() or "en0"
    out = run(["/usr/sbin/ipconfig", "getifaddr", iface], timeout=5)
    return out.strip() or None


def classify(port, iface):
    p = (port or "").lower()
    if "wi-fi" in p or "airport" in p:
        return "wifi"
    if "iphone" in p or "bluetooth pan" in p or "cellular" in p or "modem" in p:
        return "cellular"
    if "thunderbolt" in p or "ethernet" in p or "lan" in p:
        return "ethernet"
    return "wifi" if iface.startswith("en") else "other"


def network_identity():
    """Identify the network this Mac is currently on.

    Wi-Fi networks are keyed by SSID so the same network is recognised across
    reconnects and band changes. When the SSID is unavailable (it needs Location
    permission) we fall back to the gateway's MAC, which needs no permission and
    is stable per router.
    """
    route_if = detect_interface() or "en0"
    gw = detect_gateway()
    vpn = bool(re.match(r"^(utun|ppp|ipsec)", route_if))

    phys = route_if
    if vpn:
        out = run(["/sbin/route", "-n", "get", "-ifscope", "en0", "default"], timeout=5)
        phys = "en0"

    ports = hardware_ports()
    port = ports.get(phys)
    ntype = classify(port, phys)

    ssid = bssid = None
    if ntype == "wifi":
        ssid, bssid = wifi_info(phys)
    gmac = gateway_mac(gw)

    # Identity, strongest first: SSID names the network across reconnects and
    # band changes; the gateway MAC is stable per router; the gateway IP still
    # separates most networks (home 192.168.x.1 vs iPhone hotspot 172.20.10.1).
    if ntype == "wifi" and ssid:
        key, label = "wifi:" + ssid, ssid
    elif gmac:
        key, label = ntype + ":" + gmac, (port or ntype.title())
    elif gw:
        key, label = ntype + ":gw:" + gw, (port or ntype.title()) + " (" + gw + ")"
    else:
        key, label = ntype + ":" + phys, (port or phys)

    return {"key": key, "label": label, "type": ntype, "iface": phys,
            "route_iface": route_if, "ssid": ssid, "bssid": bssid,
            "gw": gw, "gw_mac": gmac, "vpn": vpn}


# ---------------------------------------------------------------- sampling ---

def ping(host, count, spacing):
    """Return {loss, rtt, jitter} or None values if unreachable."""
    out = run(["/sbin/ping", "-c", str(count), "-i", str(spacing),
               "-W", "1500", "-q", host], timeout=count * spacing + 20)
    loss = rtt = jitter = None
    m = re.search(r"([\d.]+)%\s*packet loss", out)
    if m:
        loss = float(m.group(1))
    m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", out)
    if m:
        rtt = float(m.group(2))
        jitter = float(m.group(4))
    if loss is None:
        loss = 100.0
    return {"loss": loss, "rtt": rtt, "jitter": jitter}


def iface_counters(iface):
    """Cumulative (bytes_in, bytes_out) for iface from netstat.

    -n is required: without it netstat attempts name resolution and blocks for
    tens of seconds exactly when the link is degraded, which is when we most
    need the sample.
    """
    out = run(["/usr/sbin/netstat", "-ibn"], timeout=10)
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 10 and f[0] == iface and f[2].startswith("<Link"):
            try:
                return int(f[6]), int(f[9])
            except (ValueError, IndexError):
                return None, None
    return None, None


def speedtest(url, nbytes):
    """Ranged download; returns Mbit/s or None."""
    out = run(["/usr/bin/curl", "-4", "-sL", "-o", "/dev/null",
               "-m", "30", "-r", f"0-{nbytes}",
               "-A", "hopwatch/1.0",
               "-w", "%{speed_download}", url], timeout=40)
    try:
        bps = float(out.strip().split()[0])
        return round(bps * 8 / 1_000_000, 3) if bps > 0 else None
    except (ValueError, IndexError):
        return None


def top_talkers(limit=8):
    """Best-effort per-process traffic snapshot via nettop."""
    out = run(["/usr/bin/nettop", "-P", "-x", "-l", "1",
               "-J", "bytes_in,bytes_out"], timeout=20)
    rows = []
    for line in out.splitlines():
        f = line.split()
        if len(f) < 3 or "." not in f[0]:
            continue
        try:
            bi, bo = int(f[-2]), int(f[-1])
        except ValueError:
            continue
        name = f[0].rsplit(".", 1)[0]
        if bi + bo <= 0:
            continue
        rows.append({"name": name, "bytes_in": bi, "bytes_out": bo})
    agg = {}
    for r in rows:
        a = agg.setdefault(r["name"], {"name": r["name"], "bytes_in": 0, "bytes_out": 0})
        a["bytes_in"] += r["bytes_in"]
        a["bytes_out"] += r["bytes_out"]
    ordered = sorted(agg.values(), key=lambda r: r["bytes_in"] + r["bytes_out"], reverse=True)
    return ordered[:limit]


# ------------------------------------------------- device & LAN activity ----

def _json_read(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return default


def _json_write(path, obj):
    os.makedirs(DATA, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh, indent=1)
    os.replace(tmp, path)


def connections():
    """Live connections of THIS Mac: which app is talking to which address.

    Parsed from nettop's per-connection rows. Column layout varies between TCP
    and UDP rows (UDP has no state column, some rows have no interface), so we
    locate the address field and take the next two integers as the byte counts.
    """
    out = run(["/usr/bin/nettop", "-x", "-l", "1"], timeout=25)
    rows, app, app_pid = [], None, None
    for line in out.splitlines():
        f = line.split()
        if not f:
            continue
        # every nettop row is prefixed with a timestamp field - drop it
        if re.match(r"^\d{2}:\d{2}:\d{2}\.\d+$", f[0]):
            f = f[1:]
        if not f:
            continue
        if re.match(r"^\S+\.\d+$", f[0]) and "<->" not in line:
            app, app_pid = f[0].rsplit(".", 1)
            continue
        if f[0] not in ("tcp4", "tcp6", "udp4", "udp6") or len(f) < 3:
            continue
        addr = next((x for x in f if "<->" in x), None)
        if not addr or app is None:
            continue
        remote = addr.split("<->")[1]
        if remote.startswith("*") or remote.startswith("127.") or remote == "":
            continue
        ip = remote.rsplit(":", 1)[0] if ":" in remote else remote.rsplit(".", 1)[0]
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) or ip.startswith("127."):
            continue
        nums = []
        seen_addr = False
        for x in f:
            if x is addr or "<->" in x:
                seen_addr = True
                continue
            if seen_addr and x.isdigit():
                nums.append(int(x))
                if len(nums) == 2:
                    break
        bi, bo = (nums + [0, 0])[:2]
        rows.append({"app": app, "pid": app_pid, "ip": ip, "proto": f[0],
                     "bytes_in": bi, "bytes_out": bo})
    return rows


DAEMON_INFO = {
    "apsd": "Apple Push Notification service — push for apps, Mail and iCloud",
    "mDNSResponder": "System DNS resolution and Bonjour discovery",
    "nsurlsessiond": "Background downloads and uploads for apps and iCloud",
    "cloudd": "iCloud sync",
    "bird": "iCloud Drive file sync",
    "trustd": "Certificate checking for secure connections",
    "syslogd": "System logging",
    "netbiosd": "Windows file-sharing name service",
    "rapportd": "Continuity — Handoff, AirDrop, phone calls on your Mac",
    "sharingd": "AirDrop and sharing",
    "identityservice": "Apple ID identity services",
    "akd": "Apple ID authentication",
    "AppleIDAuthAgent": "Apple ID sign-in",
    "softwareupdated": "macOS software updates",
    "commerce": "App Store purchases and downloads",
    "appstoreagent": "App Store",
    "airportd": "Wi-Fi management",
    "locationd": "Location services",
    "timed": "System clock synchronisation",
    "parsecd": "Spotlight suggestions and Siri search",
    "suggestd": "Siri suggestions",
    "symptomsd": "Apple's own network-quality monitoring",
    "assistantd": "Siri",
    "triald": "Apple feature experiments",
    "biomesyncd": "Sync between your Apple devices",
    "transparencyd": "Certificate transparency checks",
    "httpd": "A local web server running on this Mac",
    "postgres": "PostgreSQL database running locally",
    "mysqld": "MySQL database running locally",
    "redis-server": "Redis running locally",
    "docker": "Docker",
    "com.docker.backend": "Docker",
    "node": "A Node.js process",
    "python3": "A Python process",
    "ssh": "An SSH session",
    "git-remote-http": "Git talking to a remote repository",
    "Safari": "Safari browser",
    "Google Chrome": "Google Chrome browser",
    "firefox": "Firefox browser",
    "TV": "The Apple TV app",
    "Music": "Apple Music",
    "Photos": "Photos and iCloud Photos",
    "Mail": "Mail",
    "Messages": "Messages",
    "FaceTime": "FaceTime",
    "Spotify": "Spotify",
    "Dropbox": "Dropbox sync",
    "Code Helper": "Visual Studio Code",
    "Electron": "An Electron-based desktop app",
    "claude": "Claude Code CLI",
    "Claude": "Claude desktop app",
    "Slack": "Slack",
    "zoom.us": "Zoom",
    "Postman": "Postman",
    "Brave Browser": "Brave browser",
    "Arc": "Arc browser",
    "ollama": "Ollama local model runner",
    "com.apple.WebKit.Networking": "WebKit — a browser's network process",
    "WindowServer": "macOS display server",
    "configd": "System network configuration",
    "networkserviceproxy": "Apple network relay",
    "wifip2pd": "Wi-Fi peer-to-peer (AirDrop, AirPlay)",
    "ControlCenter": "macOS Control Centre",
    "nehelper": "Network extension helper",
    "remoted": "Device pairing and debugging",
    "launchd": "macOS service manager",
}


def describe_app(name, pid):
    """Human label + one-line explanation for a process seen on the network."""
    reg = _json_read(APPS, {})
    e = reg.get(name)
    if e and (time.time() - e.get("ts", 0)) < 86400:
        return e

    path = ""
    if pid:
        path = run(["/bin/ps", "-p", str(pid), "-o", "comm="], timeout=5).strip()

    label = name
    m = re.search(r"/([^/]+)\.app/", path)
    if m:
        label = m.group(1)
    elif path:
        label = os.path.basename(path) or name

    desc = DAEMON_INFO.get(label) or DAEMON_INFO.get(name)
    if not desc:
        if m:
            desc = "Application"
        elif path.startswith("/System/") or path.startswith("/usr/libexec"):
            desc = "A macOS background service"
        elif "/homebrew/" in path or path.startswith("/usr/local/bin"):
            desc = "A command-line tool"
        elif path:
            desc = "Background process"
        else:
            desc = "Unidentified process"

    e = {"name": name, "label": label, "desc": desc, "path": path,
         "ts": time.time()}
    reg[name] = e
    _json_write(APPS, reg)
    return e


def resolve_host(ip, cache):
    """Reverse-DNS with a persistent cache.

    A timeout and a genuine "no such record" both produce empty output from
    `dig +short`, so we read the status instead. On a lossy link lookups fail
    constantly; caching those as "no PTR" for a week would permanently
    mislabel destinations, so failures are retried after 30 minutes while real
    negatives are kept for a week.
    """
    e = cache.get(ip)
    if e:
        ttl = 1800 if e.get("failed") else 7 * 86400
        if (time.time() - e.get("ts", 0)) < ttl:
            return e.get("host")

    out = run(["/usr/bin/dig", "+time=3", "+tries=2", "-x", ip], timeout=12)
    host, status = None, None
    m = re.search(r"status:\s*([A-Z]+)", out)
    if m:
        status = m.group(1)
    for line in out.splitlines():
        m = re.match(r"^\S+\s+\d+\s+IN\s+PTR\s+(\S+)\.$", line.strip())
        if m:
            host = m.group(1)
            break

    failed = host is None and status not in ("NXDOMAIN", "NOERROR")
    cache[ip] = {"host": host, "ts": time.time(), "failed": failed}
    return host


def update_destinations(max_new_lookups=8):
    """Roll live connections into a persistent app -> destination registry."""
    conns = connections()
    if not conns:
        return []
    reg = _json_read(DESTS, {})
    hosts = _json_read(HOSTS, {})
    now = round(time.time(), 1)
    looked = 0
    for c in conns:
        k = c["app"] + "|" + c["ip"]
        e = reg.get(k)
        if e is None:
            e = {"app": c["app"], "ip": c["ip"], "first_seen": now,
                 "host": None, "bytes_in": 0, "bytes_out": 0}
            reg[k] = e
        e["last_seen"] = now
        e["bytes_in"] = max(e["bytes_in"], c["bytes_in"])
        e["bytes_out"] = max(e["bytes_out"], c["bytes_out"])
        if e.get("host") is None:
            cached = hosts.get(c["ip"])
            ttl = 1800 if (cached and cached.get("failed")) else 7 * 86400
            fresh = cached and (time.time() - cached.get("ts", 0)) < ttl
            if fresh:
                e["host"] = cached.get("host")
                e["no_ptr"] = cached.get("host") is None
            elif looked < max_new_lookups:
                e["host"] = resolve_host(c["ip"], hosts)
                e["no_ptr"] = e["host"] is None
                looked += 1
        if e.get("app_label") is None:
            info = describe_app(c["app"], c.get("pid"))
            e["app_label"] = info["label"]
            e["app_desc"] = info["desc"]
            e["app_path"] = info["path"]
    if len(reg) > 4000:
        for k in sorted(reg, key=lambda k: reg[k]["last_seen"])[:len(reg) - 4000]:
            del reg[k]
    _json_write(DESTS, reg)
    _json_write(HOSTS, hosts)
    return conns


def _is_random_mac(mac):
    """Locally-administered bit set => a privacy / randomised address."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def lan_devices(gw):
    """Who else is on this Wi-Fi. Presence only - see README for why."""
    if not gw:
        return []
    base = gw.rsplit(".", 1)[0]
    # Nudge the whole /24 so the ARP table is populated, then read it.
    subprocess.run(
        ["/bin/sh", "-c",
         f"for i in $(seq 1 254); do ping -c 1 -W 200 -t 1 {base}.$i >/dev/null 2>&1 & done; wait"],
        capture_output=True, timeout=45)
    out = run(["/usr/sbin/arp", "-an"], timeout=10)
    found = []
    for line in out.splitlines():
        m = re.search(r"\(([0-9.]+)\) at ([0-9a-fA-F:]{11,17})", line)
        if not m or "incomplete" in line:
            continue
        ip, mac = m.group(1), m.group(2).lower()
        if ip.endswith(".255") or int(ip.split(".")[0]) >= 224:
            continue    # broadcast / multicast are not devices
        found.append({"ip": ip, "mac": mac})
    return found


def update_devices(gw, self_ip=None):
    found = lan_devices(gw)
    reg = _json_read(DEVICES, {})
    now = round(time.time(), 1)
    seen = set()
    for d in found:
        mac = d["mac"]
        seen.add(mac)
        e = reg.get(mac)
        if e is None:
            e = {"mac": mac, "first_seen": now, "name": None,
                 "random_mac": _is_random_mac(mac)}
            reg[mac] = e
        e["ip"] = d["ip"]
        e["last_seen"] = now
        e["is_gateway"] = (d["ip"] == gw)
        e["is_self"] = (self_ip is not None and d["ip"] == self_ip)
        if not e.get("name"):
            out = run(["/usr/bin/dig", "+short", "+time=1", "+tries=1",
                       "-x", d["ip"], "@224.0.0.251", "-p", "5353"], timeout=4)
            for line in out.splitlines():
                line = line.strip().rstrip(".")
                if line and not line.startswith(";"):
                    e["name"] = line
                    break
    for mac, e in reg.items():
        e["online"] = mac in seen
    _json_write(DEVICES, reg)
    return reg


# ----------------------------------------------------------------- storage ---

_lock = threading.Lock()


def append_jsonl(path, obj):
    os.makedirs(DATA, exist_ok=True)
    with _lock:
        with open(path, "a") as fh:
            fh.write(json.dumps(obj, separators=(",", ":")) + "\n")


def read_jsonl(path, since_ts=None):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if since_ts is not None and obj.get("ts", 0) < since_ts:
                continue
            rows.append(obj)
    return rows


def read_networks():
    if not os.path.exists(NETWORKS):
        return {}
    try:
        with open(NETWORKS) as fh:
            return json.load(fh)
    except Exception:
        return {}


def touch_network(ident, ts):
    """Record/refresh this network in the registry."""
    os.makedirs(DATA, exist_ok=True)
    with _lock:
        reg = read_networks()
        e = reg.get(ident["key"])
        if e is None:
            e = {"key": ident["key"], "first_seen": ts, "vpn_seen": False}
            reg[ident["key"]] = e
        e.update({k: ident[k] for k in
                  ("label", "type", "iface", "ssid", "bssid", "gw", "gw_mac")})
        e["last_seen"] = ts
        if ident.get("vpn"):
            e["vpn_seen"] = True
        tmp = NETWORKS + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(reg, fh, indent=2)
        os.replace(tmp, NETWORKS)
    return reg


def prune(conf):
    """Drop samples older than retain_days, rewriting the file once."""
    days = conf.get("retain_days", 90)
    if not days or not os.path.exists(SAMPLES):
        return
    cutoff = time.time() - days * 86400
    rows = [r for r in read_jsonl(SAMPLES) if r.get("ts", 0) >= cutoff]
    with _lock:
        tmp = SAMPLES + ".tmp"
        with open(tmp, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r, separators=(",", ":")) + "\n")
        os.replace(tmp, SAMPLES)


# --------------------------------------------------------------- collector ---

class Collector:
    def __init__(self, conf):
        self.conf = conf
        self.prev_counters = (None, None)
        self.prev_time = None
        self.last_speedtest = 0.0
        self.net_key = None
        self.last_devices = 0.0
        self.open_incident = None
        self._load_open_incident()

    def _load_open_incident(self):
        for row in read_jsonl(INCIDENTS):
            if row.get("end") is None:
                self.open_incident = row

    def sample(self):
        conf = self.conf
        now = time.time()

        ident = network_identity()
        if ident["key"] != self.net_key:
            # Different network - byte counters are not comparable across a switch.
            self.prev_counters = (None, None)
            self.prev_time = None
            self.net_key = ident["key"]
        touch_network(ident, round(now, 1))

        pings = {}
        for t in conf["targets"]:
            pings[t["key"]] = ping(t["host"], conf["ping_count"],
                                   conf["ping_spacing_sec"])

        bi, bo = iface_counters(conf["interface"])
        traffic = None
        if bi is not None and self.prev_counters[0] is not None and self.prev_time:
            din = bi - self.prev_counters[0]
            dout = bo - self.prev_counters[1]
            secs = now - self.prev_time
            if din >= 0 and dout >= 0 and secs > 0:
                traffic = {"in": din, "out": dout, "secs": round(secs, 1)}
        if bi is not None:
            self.prev_counters = (bi, bo)
            self.prev_time = now

        speed = {}
        iv = conf.get("speedtest_interval_sec", 0)
        if iv and (now - self.last_speedtest) >= iv:
            for st in conf.get("speedtests", []):
                speed[st["key"]] = speedtest(st["url"], conf["speedtest_bytes"])
            self.last_speedtest = now

        row = {"ts": round(now, 1), "pings": pings, "net": ident["key"]}
        if ident.get("vpn"):
            row["vpn"] = True
        if traffic:
            row["traffic"] = traffic
        if speed:
            row["speed"] = speed
        append_jsonl(SAMPLES, row)
        self._track_incident(row)
        return row

    def _track_incident(self, row):
        warn = self.conf["loss_warn_pct"]
        intl = (row["pings"].get("intl") or {}).get("loss")
        lan = (row["pings"].get("lan") or {}).get("loss")
        if intl is None:
            return
        # Only call it an ISP incident when the LAN is clean - otherwise it is local.
        local_ok = lan is not None and lan < warn
        degraded = intl >= warn and local_ok

        if degraded and self.open_incident is None:
            self.open_incident = {
                "start": row["ts"], "end": None,
                "peak_loss": intl, "samples": 1,
            }
            append_jsonl(INCIDENTS, self.open_incident)
        elif degraded and self.open_incident:
            self.open_incident["peak_loss"] = max(self.open_incident["peak_loss"], intl)
            self.open_incident["samples"] += 1
            self._rewrite_incidents()
        elif not degraded and self.open_incident:
            self.open_incident["end"] = row["ts"]
            self._rewrite_incidents()
            self.open_incident = None

    def _rewrite_incidents(self):
        rows = read_jsonl(INCIDENTS)
        if not rows:
            return
        rows[-1] = self.open_incident
        with _lock:
            tmp = INCIDENTS + ".tmp"
            with open(tmp, "w") as fh:
                for r in rows:
                    fh.write(json.dumps(r, separators=(",", ":")) + "\n")
            os.replace(tmp, INCIDENTS)

    def activity_loop(self):
        """Device activity + LAN discovery, on their own thread.

        A /24 sweep plus reverse lookups can take longer than the sample
        interval, so this must never run on the ping path - otherwise the
        loss/latency cadence drifts exactly when the network is slow.
        """
        last_dev = 0.0
        while True:
            try:
                update_destinations()
            except Exception as exc:
                print(f"[hopwatch] destinations: {exc}", file=sys.stderr)
            if time.time() - last_dev >= 300:
                try:
                    update_devices(detect_gateway(), self_ip())
                except Exception as exc:
                    print(f"[hopwatch] devices: {exc}", file=sys.stderr)
                last_dev = time.time()
            time.sleep(60)

    def loop(self):
        last_prune = 0.0
        while True:
            started = time.time()
            try:
                self.sample()
            except Exception as exc:
                print(f"[hopwatch] sample error: {exc}", file=sys.stderr)
            if time.time() - last_prune > 86400:
                try:
                    prune(self.conf)
                except Exception:
                    pass
                last_prune = time.time()
            elapsed = time.time() - started
            time.sleep(max(5.0, self.conf["sample_interval_sec"] - elapsed))


# ----------------------------------------------------------------- summary ---

def cycle_start(conf):
    day = max(1, min(28, int(conf.get("cycle_start_day", 1))))
    now = datetime.now()
    start = now.replace(day=day, hour=0, minute=0, second=0, microsecond=0)
    if start > now:
        start = (start - timedelta(days=31)).replace(day=day)
    return start.timestamp()


def summarise(conf, rows):
    out = {
        "now": time.time(),
        "latest": rows[-1] if rows else None,
        "targets": conf["targets"],
        "speedtests": conf.get("speedtests", []),
        "thresholds": {"warn": conf["loss_warn_pct"], "crit": conf["loss_crit_pct"]},
        "plan_down_mbps": conf["plan_down_mbps"],
        "fup_cap_gb": conf["fup_cap_gb"],
        "interface": conf["interface"],
        "sample_interval_sec": conf["sample_interval_sec"],
    }
    try:
        out["network"] = network_identity()
    except Exception:
        out["network"] = None

    midnight = datetime.now().replace(hour=0, minute=0, second=0,
                                      microsecond=0).timestamp()
    cyc = cycle_start(conf)
    tot = {"today_in": 0, "today_out": 0, "cycle_in": 0, "cycle_out": 0}
    for r in rows:
        tr = r.get("traffic")
        if not tr:
            continue
        if r["ts"] >= cyc:
            tot["cycle_in"] += tr["in"]
            tot["cycle_out"] += tr["out"]
        if r["ts"] >= midnight:
            tot["today_in"] += tr["in"]
            tot["today_out"] += tr["out"]
    out["usage"] = tot
    out["cycle_start"] = cyc

    # last known speedtest per key
    last_speed = {}
    for r in rows:
        for k, v in (r.get("speed") or {}).items():
            if v is not None:
                last_speed[k] = {"mbps": v, "ts": r["ts"]}
    out["last_speed"] = last_speed

    # rolling means over the last hour
    hour_ago = time.time() - 3600
    recent = [r for r in rows if r["ts"] >= hour_ago]
    means = {}
    for t in conf["targets"]:
        k = t["key"]
        losses = [r["pings"][k]["loss"] for r in recent
                  if r.get("pings", {}).get(k, {}).get("loss") is not None]
        rtts = [r["pings"][k]["rtt"] for r in recent
                if r.get("pings", {}).get(k, {}).get("rtt") is not None]
        means[k] = {
            "loss": round(sum(losses) / len(losses), 2) if losses else None,
            "rtt": round(sum(rtts) / len(rtts), 1) if rtts else None,
        }
    out["hour_means"] = means
    return out


def network_stats(conf, rows):
    """Registry entries enriched with what we measured on each network."""
    reg = read_networks()
    agg = {}
    for r in rows:
        k = r.get("net")
        if not k:
            continue
        a = agg.setdefault(k, {"samples": 0, "loss": [], "rtt": [],
                               "in": 0, "out": 0, "last": 0, "vpn": 0,
                               "speed": []})
        a["samples"] += 1
        a["last"] = max(a["last"], r["ts"])
        if r.get("vpn"):
            a["vpn"] += 1
        p = (r.get("pings") or {}).get("intl") or {}
        if p.get("loss") is not None:
            a["loss"].append(p["loss"])
        if p.get("rtt") is not None:
            a["rtt"].append(p["rtt"])
        tr = r.get("traffic")
        if tr:
            a["in"] += tr["in"]
            a["out"] += tr["out"]
        sp = (r.get("speed") or {}).get("intl")
        if sp is not None:
            a["speed"].append(sp)

    cur = None
    try:
        cur = network_identity()["key"]
    except Exception:
        pass

    out = []
    for k, e in reg.items():
        a = agg.get(k, {"samples": 0, "loss": [], "rtt": [], "in": 0,
                        "out": 0, "last": e.get("last_seen", 0), "vpn": 0,
                        "speed": []})
        mean = lambda xs: round(sum(xs) / len(xs), 2) if xs else None
        out.append({
            "key": k,
            "label": e.get("label") or k,
            "type": e.get("type", "other"),
            "ssid": e.get("ssid"),
            "gw": e.get("gw"),
            "gw_mac": e.get("gw_mac"),
            "first_seen": e.get("first_seen"),
            "last_seen": max(e.get("last_seen", 0), a["last"]),
            "current": k == cur,
            "vpn_seen": bool(e.get("vpn_seen")),
            "vpn_samples": a["vpn"],
            "samples": a["samples"],
            "loss_avg": mean(a["loss"]),
            "loss_max": round(max(a["loss"]), 1) if a["loss"] else None,
            "rtt_avg": mean(a["rtt"]),
            "speed_avg": mean(a["speed"]),
            "bytes_in": a["in"],
            "bytes_out": a["out"],
        })
    out.sort(key=lambda x: (not x["current"], -(x["last_seen"] or 0)))
    return out


def build_report(conf, hours=24):
    since = time.time() - hours * 3600
    rows = read_jsonl(SAMPLES, since)
    incs = [i for i in read_jsonl(INCIDENTS) if i.get("start", 0) >= since]
    lines = []
    A = lines.append
    A("INTERNET PERFORMANCE REPORT")
    A("=" * 60)
    A(f"Generated      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')}")
    A(f"Window         : last {hours}h   ({len(rows)} samples)")
    A(f"Plan           : {conf['plan_down_mbps']} Mbps down")
    A(f"Interface      : {conf['interface']}")
    A("")
    A("PACKET LOSS AND LATENCY BY HOP")
    A("-" * 60)
    A(f"{'Hop':<24}{'Host':<18}{'Loss avg':>10}{'Loss max':>10}{'RTT avg':>10}")
    for t in conf["targets"]:
        k = t["key"]
        ls = [r["pings"][k]["loss"] for r in rows
              if r.get("pings", {}).get(k, {}).get("loss") is not None]
        rt = [r["pings"][k]["rtt"] for r in rows
              if r.get("pings", {}).get(k, {}).get("rtt") is not None]
        if not ls:
            continue
        A(f"{t['label'][:23]:<24}{t['host']:<18}"
          f"{sum(ls)/len(ls):>9.2f}%{max(ls):>9.1f}%"
          f"{(sum(rt)/len(rt) if rt else 0):>9.1f}ms")
    A("")
    A("DEGRADATION EPISODES  (international loss >= "
      f"{conf['loss_warn_pct']}% while home network at 0%)")
    A("-" * 60)
    if not incs:
        A("None recorded in this window.")
    for i in incs:
        st = datetime.fromtimestamp(i["start"]).strftime("%Y-%m-%d %H:%M")
        if i.get("end"):
            en = datetime.fromtimestamp(i["end"]).strftime("%H:%M")
            mins = max(1, int((i["end"] - i["start"]) / 60))
            A(f"{st} -> {en}  ({mins} min)   peak loss {i['peak_loss']:.1f}%")
        else:
            A(f"{st} -> ONGOING            peak loss {i['peak_loss']:.1f}%")
    A("")
    A("THROUGHPUT MEASUREMENTS")
    A("-" * 60)
    for st in conf.get("speedtests", []):
        vals = [r["speed"][st["key"]] for r in rows
                if (r.get("speed") or {}).get(st["key"]) is not None]
        if vals:
            A(f"{st['label']:<24}min {min(vals):>7.2f}   "
              f"avg {sum(vals)/len(vals):>7.2f}   max {max(vals):>7.2f}  Mbit/s")
    A("")
    A("DATA USAGE")
    A("-" * 60)
    s = summarise(conf, read_jsonl(SAMPLES))
    u = s["usage"]
    A(f"Today      down {u['today_in']/1e9:.2f} GB   up {u['today_out']/1e9:.2f} GB")
    A(f"Cycle      down {u['cycle_in']/1e9:.2f} GB   up {u['cycle_out']/1e9:.2f} GB"
      f"   (FUP cap {conf['fup_cap_gb']} GB)")
    A("")
    A("Interpretation: loss measured at the home router and inside the ISP's")
    A("domestic network, compared against international destinations. Loss that")
    A("appears only beyond the ISP border, while the home network stays at 0%,")
    A("indicates congestion upstream of the subscriber line rather than a local")
    A("or capacity fault.")
    return "\n".join(lines)


# ------------------------------------------------------------------ server ---

class Handler(BaseHTTPRequestHandler):
    conf = None
    server_version = "hopwatch"

    def log_message(self, *_args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        path = u.path
        try:
            if path in ("/", "/index.html"):
                fp = os.path.join(BASE, "dashboard.html")
                with open(fp, "rb") as fh:
                    return self._send(200, fh.read(), "text/html; charset=utf-8")

            if path == "/api/status":
                rows = read_jsonl(SAMPLES)
                return self._send(200, json.dumps(summarise(self.conf, rows)))

            if path == "/api/samples":
                hours = float(q.get("hours", ["6"])[0])
                rows = read_jsonl(SAMPLES, time.time() - hours * 3600)
                net = q.get("net", [None])[0]
                if net:
                    rows = [r for r in rows if r.get("net") == net]
                return self._send(200, json.dumps({"samples": rows}))

            if path == "/api/networks":
                hours = float(q.get("hours", ["720"])[0])
                rows = read_jsonl(SAMPLES, time.time() - hours * 3600)
                return self._send(200, json.dumps(
                    {"networks": network_stats(self.conf, rows)}))

            if path == "/api/incidents":
                return self._send(200, json.dumps({"incidents": read_jsonl(INCIDENTS)}))

            if path == "/api/activity":
                reg = _json_read(DESTS, {})
                rows = list(reg.values())
                # one app identity, applied to every row for that process -
                # rows for connections that are no longer live may predate it
                ident = {}
                for r in rows:
                    if r.get("app_desc") and r["app"] not in ident:
                        ident[r["app"]] = (r.get("app_label"), r["app_desc"],
                                           r.get("app_path"))
                for r in rows:
                    r["total"] = r.get("bytes_in", 0) + r.get("bytes_out", 0)
                    if r["app"] in ident:
                        lb, ds, pt = ident[r["app"]]
                        r["app_label"] = r.get("app_label") or lb
                        r["app_desc"] = r.get("app_desc") or ds
                        r["app_path"] = r.get("app_path") or pt
                    if not r.get("app_desc"):
                        # no live connection to inspect - fall back to the
                        # known-daemon dictionary by process name
                        r["app_desc"] = DAEMON_INFO.get(
                            r.get("app_label") or r["app"], "")
                apps = {}
                for r in rows:
                    a = apps.setdefault(r["app"], {
                        "app": r["app"],
                        "label": r.get("app_label") or r["app"],
                        "desc": r.get("app_desc") or "",
                        "path": r.get("app_path") or "",
                        "total": 0, "bytes_in": 0, "bytes_out": 0,
                        "destinations": 0})
                    a["total"] += r["total"]
                    a["bytes_in"] += r.get("bytes_in", 0)
                    a["bytes_out"] += r.get("bytes_out", 0)
                    a["destinations"] += 1
                top_apps = sorted(apps.values(), key=lambda a: a["total"],
                                  reverse=True)[:12]
                # destinations read as a log: most recently contacted first
                rows.sort(key=lambda r: r.get("last_seen", 0), reverse=True)
                return self._send(200, json.dumps(
                    {"apps": top_apps, "destinations": rows[:200]}))

            if path == "/api/devices":
                reg = _json_read(DEVICES, {})
                rows = sorted(reg.values(),
                              key=lambda d: (not d.get("online"),
                                             -(d.get("last_seen") or 0)))
                return self._send(200, json.dumps({"devices": rows}))

            if path == "/api/talkers":
                return self._send(200, json.dumps({"talkers": top_talkers()}))

            if path == "/api/report":
                hours = float(q.get("hours", ["24"])[0])
                return self._send(200, build_report(self.conf, hours),
                                  "text/plain; charset=utf-8")

            return self._send(404, json.dumps({"error": "not found"}))
        except Exception as exc:
            return self._send(500, json.dumps({"error": str(exc)}))


def serve(conf, collect=True):
    write_default_conf()
    os.makedirs(DATA, exist_ok=True)
    if collect:
        col = Collector(conf)
        threading.Thread(target=col.loop, daemon=True).start()
        threading.Thread(target=col.activity_loop, daemon=True).start()
    Handler.conf = conf
    socketserver.TCPServer.allow_reuse_address = True
    with ThreadingHTTPServer(("127.0.0.1", conf["port"]), Handler) as httpd:
        print(f"[hopwatch] dashboard  ->  http://127.0.0.1:{conf['port']}")
        print(f"[hopwatch] interface  {conf['interface']}   "
              f"sampling every {conf['sample_interval_sec']}s")
        print(f"[hopwatch] data       {SAMPLES}")
        print("[hopwatch] ctrl-c to stop")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[hopwatch] stopped")


def main():
    ap = argparse.ArgumentParser(description="local internet performance monitor")
    ap.add_argument("--once", action="store_true", help="take one sample, exit")
    ap.add_argument("--serve-only", action="store_true", help="serve without collecting")
    ap.add_argument("--report", action="store_true", help="print ISP evidence report")
    ap.add_argument("--hours", type=float, default=24, help="report window")
    args = ap.parse_args()

    write_default_conf()
    conf = load_conf()

    if args.report:
        print(build_report(conf, args.hours))
        return
    if args.once:
        row = Collector(conf).sample()
        print(json.dumps(row, indent=2))
        return
    serve(conf, collect=not args.serve_only)


if __name__ == "__main__":
    main()
