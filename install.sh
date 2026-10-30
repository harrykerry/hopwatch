#!/bin/sh
# hopwatch installer - creates the hopwatch-* commands and the launchd agent.
set -e

REPO=$(cd "$(dirname "$0")" && pwd)
LABEL=com.hopwatch.agent
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
PORT=$(python3 -c "import json,sys;print(json.load(open('$REPO/hopwatch.conf.json'))['port'])" 2>/dev/null || echo 8765)

# Pick a bin directory that is already on PATH and writable.
BIN=""
for d in /opt/homebrew/bin /usr/local/bin "$HOME/.local/bin" "$HOME/bin"; do
  case ":$PATH:" in *":$d:"*) [ -d "$d" ] && [ -w "$d" ] && BIN="$d" && break ;; esac
done
if [ -z "$BIN" ]; then
  BIN="$HOME/.local/bin"; mkdir -p "$BIN"
  echo "note: $BIN is not on your PATH. Add this to your shell profile:"
  echo "      export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

command -v python3 >/dev/null 2>&1 || { echo "error: python3 not found"; exit 1; }

mkdir -p "$REPO/data" "$HOME/Library/LaunchAgents"

cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/env</string><string>python3</string>
    <string>$REPO/hopwatch.py</string>
  </array>
  <key>WorkingDirectory</key><string>$REPO</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$REPO/data/hopwatch.log</string>
  <key>StandardErrorPath</key><string>$REPO/data/hopwatch.err</string>
</dict>
</plist>
PLIST_EOF

write_cmd() { cat > "$BIN/$1"; chmod +x "$BIN/$1"; }

write_cmd hopwatch-start <<CMD_EOF
#!/bin/sh
# Start hopwatch and keep it running across restarts.
PORT=$PORT; LABEL=$LABEL; REPO="$REPO"
PLIST="\$HOME/Library/LaunchAgents/\$LABEL.plist"
UID_N=\$(id -u)
[ -f "\$PLIST" ] || { echo "hopwatch: agent missing - run \$REPO/install.sh"; exit 1; }
launchctl bootstrap "gui/\$UID_N" "\$PLIST" 2>/dev/null || launchctl load -w "\$PLIST" 2>/dev/null
launchctl enable "gui/\$UID_N/\$LABEL" 2>/dev/null
i=0
while [ \$i -lt 15 ]; do
  if lsof -nP -iTCP:\$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "hopwatch started  ->  http://127.0.0.1:\$PORT"
    echo "restart survival: ON"
    exit 0
  fi
  sleep 1; i=\$((i+1))
done
echo "hopwatch did not come up; see \$REPO/data/hopwatch.err"; exit 1
CMD_EOF

write_cmd hopwatch-stop <<CMD_EOF
#!/bin/sh
# Stop hopwatch and disable restart survival.
PORT=$PORT; LABEL=$LABEL
PLIST="\$HOME/Library/LaunchAgents/\$LABEL.plist"
UID_N=\$(id -u)
launchctl bootout "gui/\$UID_N/\$LABEL" 2>/dev/null || launchctl unload -w "\$PLIST" 2>/dev/null
launchctl disable "gui/\$UID_N/\$LABEL" 2>/dev/null
pid=\$(lsof -nP -iTCP:\$PORT -sTCP:LISTEN -t 2>/dev/null)
[ -n "\$pid" ] && kill \$pid 2>/dev/null
sleep 1
if lsof -nP -iTCP:\$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
  echo "hopwatch still listening on \$PORT - try again"
else
  echo "hopwatch stopped"; echo "restart survival: OFF"
fi
CMD_EOF

write_cmd hopwatch-status <<CMD_EOF
#!/bin/sh
PORT=$PORT; LABEL=$LABEL; UID_N=\$(id -u)
if lsof -nP -iTCP:\$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
  echo "hopwatch running  ->  http://127.0.0.1:\$PORT"
else echo "hopwatch stopped"; fi
if launchctl print "gui/\$UID_N/\$LABEL" >/dev/null 2>&1; then
  echo "restart survival: ON"
else echo "restart survival: OFF"; fi
CMD_EOF

write_cmd hopwatch-report <<CMD_EOF
#!/bin/sh
exec python3 "$REPO/hopwatch.py" --report --hours "\${1:-24}"
CMD_EOF

echo "installed into $BIN:"
echo "  hopwatch-start  hopwatch-stop  hopwatch-status  hopwatch-report"
echo "launchd agent: $PLIST"
echo
echo "run 'hopwatch-start', then open http://127.0.0.1:$PORT"
