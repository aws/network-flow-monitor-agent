#!/bin/bash
set -e

echo "Starting NFM Agent extension..."
echo "Extension ID: ${EXTENSION_ID}"

if ! systemctl start network-flow-monitor.service; then
    echo "Error: Failed to start network-flow-monitor.service" >&2
    systemctl status network-flow-monitor.service >&2 || true
    exit 1
fi

echo "NFM Agent started"
exit 0
