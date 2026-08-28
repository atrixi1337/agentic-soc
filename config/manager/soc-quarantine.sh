#!/bin/bash
# soc-quarantine.sh — active response: move the offending file to /quarantine.
# Called by Wazuh active response with: alert_id, rule_id, filename, ...
# Wazuh passes the target file path as an arg in active-response mode.
LOG="/var/ossec/logs/active-responses.log"
QUAR_DIR="/quarantine"
mkdir -p "$QUAR_DIR"
FILE="$1"
TS=$(date '+%Y-%m-%d %H:%M:%S')
if [ -n "$FILE" ] && [ -f "$FILE" ]; then
  mv -f "$FILE" "$QUAR_DIR/" 2>/dev/null && \
    echo "$TS QUARANTINED $FILE -> $QUAR_DIR/" >> "$LOG"
else
  echo "$TS soc-quarantine: no valid file arg ($FILE)" >> "$LOG"
fi
exit 0
