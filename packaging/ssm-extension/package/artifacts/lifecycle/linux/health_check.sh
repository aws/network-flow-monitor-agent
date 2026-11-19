#!/bin/bash

SERVICE=network-flow-monitor.service
# The first publish lands ~25-35s after start (30s period +/- 5s jitter), so a freshly started
# agent has no successful publish yet. Within this window, it is healthy unless a publish failed.
STARTUP_GRACE_SECONDS=120

# Check 1: service must be running
if ! systemctl is-active --quiet "$SERVICE"; then
    STATE=$(systemctl show -p ActiveState --value "$SERVICE" 2>/dev/null || echo "unknown")
    echo "NFM Agent is unhealthy: service state is ${STATE}" >&2
    exit 1
fi

# Seconds since the service became active, from the monotonic clock. Empty if unknown.
service_age_seconds() {
    local active_us uptime_s
    active_us=$(systemctl show -p ActiveEnterTimestampMonotonic --value "$SERVICE" 2>/dev/null)
    uptime_s=$(cut -d' ' -f1 /proc/uptime 2>/dev/null)
    case "$active_us" in ''|0|*[!0-9]*) return ;; esac
    [ -n "$uptime_s" ] || return
    awk -v up="$uptime_s" -v act="$active_us" 'BEGIN { printf "%d\n", up - act / 1000000 }'
}

# Check 2: agent must have published successfully within the last 2 minutes
# The agent logs structured JSON with "status":200 on each successful publish (every ~30s by default).
# Try journalctl first; fall back to syslog/messages if journal is unavailable.
RECENT_LOGS=""
if command -v journalctl >/dev/null 2>&1; then
    RECENT_LOGS=$(journalctl -u "$SERVICE" --since "2 minutes ago" --no-pager -o cat 2>/dev/null)
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

if [ -n "$RECENT_LOGS" ] && echo "$RECENT_LOGS" | grep -q '"status":200'; then
    echo "NFM Agent is healthy"
    exit 0
fi

AGE=$(service_age_seconds)
if [ -n "$AGE" ] && [ "$AGE" -lt "$STARTUP_GRACE_SECONDS" ]; then
    # Only this run's logs count, so a failure from a previous start does not fail a new one.
    SINCE_START=""
    if command -v journalctl >/dev/null 2>&1; then
        SINCE_START=$(journalctl -u "$SERVICE" --since "-${AGE}s" --no-pager -o cat 2>/dev/null)
    fi
    if echo "$SINCE_START" | grep -qE '"status":([013-9][0-9][0-9]|2[1-9][0-9]|20[1-9])|Error sending request|Error getting credentials'; then
        echo "NFM Agent is unhealthy: publish failed since start" >&2
        exit 1
    fi
    echo "NFM Agent is healthy: started ${AGE}s ago, waiting for first publish"
    exit 0
fi

echo "NFM Agent is unhealthy: no successful publish in the last 2 minutes" >&2
exit 1
