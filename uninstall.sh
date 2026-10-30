#!/bin/sh
# Remove the hopwatch commands and launchd agent. Collected data is left alone.
LABEL=com.hopwatch.agent
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || launchctl unload -w "$PLIST" 2>/dev/null
rm -f "$PLIST"
for d in /opt/homebrew/bin /usr/local/bin "$HOME/.local/bin" "$HOME/bin"; do
  rm -f "$d/hopwatch-start" "$d/hopwatch-stop" "$d/hopwatch-status" "$d/hopwatch-report"
done
echo "hopwatch commands and launchd agent removed."
echo "Collected data was left in place; delete the repo's data/ folder to remove it."
