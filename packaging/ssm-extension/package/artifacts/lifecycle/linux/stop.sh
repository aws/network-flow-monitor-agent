#!/bin/bash

echo "Stopping NFM Agent extension..."
echo "Extension ID: ${EXTENSION_ID}"

systemctl stop network-flow-monitor.service 2>/dev/null || true

echo "NFM Agent stopped"
exit 0
