#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

RAW_STATE=$(systemctl show -p ActiveState --value network-flow-monitor.service 2>/dev/null || echo "unknown")
STATE=$(map_systemd_state "$RAW_STATE")

START_TIME=$(systemctl show -p ExecMainStartTimestamp --value network-flow-monitor.service 2>/dev/null || echo "")
if [ -z "$START_TIME" ] || [ "$START_TIME" = "" ]; then
    START_TIME="none"
fi

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

printf '{\n  "extension_id": "%s",\n  "state": "%s",\n  "start_time": "%s",\n  "timestamp": "%s"\n}\n' \
    "${EXTENSION_ID}" "${STATE}" "${START_TIME}" "${TIMESTAMP}"

exit 0
