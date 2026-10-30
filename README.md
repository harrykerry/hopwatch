# hopwatch

A local network monitor for macOS that answers the question speed tests can't:
**is this my Wi-Fi, my ISP, or the service I'm using?**

No account, no cloud, no dependencies. One Python file and a dashboard that runs
on `127.0.0.1` and never sends your data anywhere.

---

## Why this exists

A streaming app keeps buffering. You run a speed test — it looks fine. Netflix and
YouTube work perfectly on the same network, so it "must be the app."

A single speed number can't resolve that, because the fault is usually not bandwidth.
What matters is **where** packets are being lost, and that only shows up when you
measure several points on the path at the same time:

| Hop | Loss | What it means |
|---|---|---|
| Your router | 0.0% | your home network is fine |
| ISP edge | 2.0% | loss begins here |
| International | 9.0% | and grows past their border |
| In-country (ISP-cached) | 0.0% | cached services bypass the problem |

That table is a diagnosis. Your equipment is clean, your ISP's upstream is congested,
and the services that still work do so because they're served from inside your ISP's
network. No amount of paying for a faster plan fixes it — TCP throughput collapses
under packet loss regardless of how wide the pipe is.

hopwatch takes that measurement every 60 seconds, around the clock, and keeps the
receipts.

---

## What it does

**Per-hop loss, latency and jitter.** Four targets every minute: your router, your
ISP's first public hop, an international destination, and a service cached inside
your ISP. The comparison between them is the whole point.

**Throughput**, measured periodically against an international and an in-country
endpoint, so you can watch the two diverge.

**Data usage**, read from interface byte counters, with a fair-usage meter for
today and the current billing cycle.

**Degradation episodes.** When international loss crosses a threshold *while your
own network stays clean*, hopwatch opens a timestamped incident and closes it when
the path recovers. This is what turns "it sometimes buffers" into evidence.

**An ISP report.** `hopwatch-report` prints a plain-text summary — per-hop loss,
every episode with timestamps and duration, throughput, usage — ready to paste into
a support ticket.

**Per-connection tracking.** Every sample is tagged with the network it was taken
on, identified by SSID where available, falling back to the gateway's MAC and then
its IP. Home Wi-Fi, a café, and phone tethering never get averaged together. Byte
counters reset on a switch, so usage is never charged to the wrong connection.

**VPN detection.** Samples taken over a tunnel are flagged, so VPN-on and VPN-off
measurements stay comparable. (Useful: if a VPN fixes your problem, that's strong
evidence the fault is your ISP's routing, since a VPN cannot add capacity.)

**App activity.** Which app on this Mac talked to which address, and how much.
Hover any app for a plain-English description of what it is; hover any destination
for what it resolves to and when it was first and last contacted.

**Devices on your Wi-Fi.** Who else is connected, with presence history and
device names where they publish one.

---

## Requirements

- macOS (uses `ping`, `traceroute`, `netstat`, `nettop`, `arp`, `dig`, `launchd`)
- Python 3.9+ — **standard library only**, nothing to `pip install`

## Install

```bash
git clone https://github.com/harrykerry/hopwatch.git
cd hopwatch
./install.sh
hopwatch-start
```

Then open **http://127.0.0.1:8765**.

`install.sh` works from wherever you cloned it. It picks a directory already on your
`PATH`, installs four commands, and writes a `launchd` agent pointing at your clone.

## Commands

| Command | What it does |
|---|---|
| `hopwatch-start` | Starts it **and** keeps it running across restarts |
| `hopwatch-stop` | Stops it **and** disables restart survival |
| `hopwatch-status` | Reports both: running state and restart survival |
| `hopwatch-report [hours]` | Prints the ISP evidence report (default 24h) |

To remove everything: `./uninstall.sh` (your collected data is left alone).

Prefer to run it in the foreground instead? `python3 hopwatch.py`, ctrl-c to stop.
Other modes: `--once` takes a single sample, `--serve-only` views existing data
without collecting, `--report` prints the report.

---

## Using the dashboard

The landing page is a card per connection — nothing else. Each card shows that
network's loss, latency, data used and when it was last seen, plus a button that
opens that network's router admin page.

Pick a card and you get the full dashboard **scoped to that network**: stat tiles,
packet loss and latency by hop, throughput, traffic, degradation episodes, app
activity and connected devices. "All connections" takes you back.

The view lives in the URL (`#all`, `#n=<network>`), so browser back works and you
can bookmark one network's page.

Every chart has a table view, works in light and dark mode, and the dashboard loads
no external resources — so it still renders when your internet is down.

---

## Configuration

Edit `hopwatch.conf.json` (written on first run) and restart.

| Key | Default | Meaning |
|---|---|---|
| `sample_interval_sec` | `60` | How often to measure loss and latency |
| `speedtest_interval_sec` | `3600` | How often to measure throughput. `0` disables |
| `speedtest_bytes` | `1500000` | Bytes per throughput test |
| `ping_count` | `10` | Probes per hop per sample |
| `loss_warn_pct` / `loss_crit_pct` | `3` / `8` | Thresholds for Unstable / Degraded |
| `plan_down_mbps` | `15` | Your plan speed, shown for reference |
| `fup_cap_gb` | `500` | Your fair-usage cap — **set this to yours** |
| `cycle_start_day` | `1` | Day of month your billing cycle starts |
| `retain_days` | `90` | How long to keep samples |
| `port` | `8765` | Dashboard port, bound to `127.0.0.1` only |
| `targets` | auto | Hops to ping (see below) |

Targets resolve themselves on first run: `auto` is your default gateway,
`auto-isp` traceroutes out and picks the first public hop, and `auto-cache`
resolves a service your ISP is likely to cache. Set explicit IPs if you'd rather
choose them yourself.

### Data cost

Pings cost about **10 MB/day**. Throughput tests dominate everything else: at the
defaults (1.5 MB × 2 endpoints, hourly) that's roughly **70 MB/day**. Set
`speedtest_interval_sec` to `0` and the whole thing costs under 10 MB/month while
still logging every loss episode.

---

## Where your data lives

Everything stays in `data/` as append-only JSON Lines — easy to grep, easy to load
elsewhere, easy to delete.

```
data/samples.jsonl       one object per sample
data/incidents.jsonl     one object per degradation episode
data/networks.json       networks seen
data/devices.json        devices seen on your Wi-Fi
data/destinations.json   app -> address history
```

`data/` and `hopwatch.conf.json` are gitignored, because between them they describe
your network, the devices on it and what your Mac talks to. **Don't commit them**,
and check any screenshot before publishing it — the dashboard shows your SSID,
gateway and device addresses.

---

## What it can't do

Being straight about the limits, because other tools are not:

- **It cannot see other devices' traffic.** On a switched network their packets are
  never delivered to your Mac. hopwatch can tell you *who is connected*; it cannot
  tell you what they are doing. Any tool claiming otherwise is either reading your
  router's API or ARP-spoofing your own network.
- **No parental controls.** Blocking a device, capping its hours or filtering what
  it reaches are router functions. Use the Open router button, or point your
  router's DNS at a filtering resolver to cover every device at once.
- **No URLs or page contents.** Traffic is HTTPS; paths and content are encrypted
  and invisible to anything running on the device. You get app, address and volume.
- **Hostnames come from reverse DNS**, which many CDN addresses simply don't
  publish — those rows show an IP, and the tooltip says why. macOS redacts DNS
  queries in the unified log, so the domains your Mac actually looked up are not
  available without installing a logging profile.
- **Usage is read from interface counters**, so it includes local traffic (AirDrop,
  Time Machine, printers) and is a close approximation of your ISP's meter, not an
  exact match.
- **Loss is measured with ICMP.** Some routers deprioritise ICMP under load, so a
  single hop can look slightly worse than it is. The comparison *between* hops is
  the reliable signal, and that's what the tool is built around.

---

## Troubleshooting

**`command not found` after installing.** `install.sh` fell back to a directory not
on your `PATH`. It prints which one and the line to add to your shell profile.

**The dashboard is empty.** Traffic rates need two consecutive samples; the device
list needs one sweep (up to five minutes). Check `data/hopwatch.err`.

**Device discovery finds nothing.** Some networks enable client isolation, which
blocks devices from seeing each other. That's the network's policy, not a bug.

**Throughput readings look low.** That's the measurement working. Compare them
against the loss figures for the same period before blaming your plan.

---

## License

MIT — see [LICENSE](LICENSE).
