#!/bin/bash

# Check 1: service must be running
if ! systemctl is-active --quiet network-flow-monitor.service; then
    STATE=$(systemctl show -p ActiveState --value network-flow-monitor.service 2>/dev/null || echo "unknown")
    echo "NFM Agent is unhealthy: service state is ${STATE}" >&2
    exit 1
fi

# Check 2: agent must have published successfully within the last 2 minutes
# The agent logs structured JSON with "status":200 on each successful publish (every ~30s by default).
# Try journalctl first; fall back to syslog/messages if journal is unavailable.
RECENT_LOGS=""
if command -v journalctl >/dev/null 2>&1; then
    RECENT_LOGS=$(journalctl -u network-flow-monitor.service --since "2 minutes ago" --no-pager -o cat 2>/dev/null)
fi

if [ -z "$RECENT_LOGS" ]; then
    # Fallback: check last 200 lines of syslog/messages for recent NFM entries
    for LOG_FILE in /var/log/syslog /var/log/messages; do
        if [ -f "$LOG_FILE" ]; then
            RECENT_LOGS=$(tail -200 "$LOG_FILE" 2>/dev/null | grep "network-flow-monitor")
            [ -n "$RECENT_LOGS" ] && break
        fi
    done
fi

if [ -n "$RECENT_LOGS" ]; then
    if ! echo "$RECENT_LOGS" | grep -q '"status":200'; then
        echo "NFM Agent is unhealthy: no successful publish in the last 2 minutes" >&2
        exit 1
    fi
fi

echo "NFM Agent is healthy"
exit 0
