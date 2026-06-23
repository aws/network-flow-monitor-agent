#!/bin/bash

if systemctl is-active --quiet network-flow-monitor.service; then
    echo "NFM Agent is healthy"
    exit 0
fi

STATE=$(systemctl show -p ActiveState --value network-flow-monitor.service 2>/dev/null || echo "unknown")
echo "NFM Agent is unhealthy: service state is ${STATE}" >&2
exit 1
