#!/bin/bash
set -o nounset

# Uninstalls the agent and verifies cleanup.
# Usage: uninstall-agent.sh <pkg_type>
#   pkg_type: rpm | binary

PKG_TYPE="${1:?Usage: uninstall-agent.sh <pkg_type>}"

echo "=== Uninstalling agent (${PKG_TYPE}) ==="

if [ "$PKG_TYPE" = "rpm" ] && rpm -q network-flow-monitor-agent &>/dev/null; then
  rpm -e network-flow-monitor-agent

  if [ -f /opt/aws/network-flow-monitor/network-flow-monitor-agent ]; then
    echo "WARN: Binary still present after uninstall"
  else
    echo "Binary removed: OK"
  fi

  if systemctl is-enabled network-flow-monitor.service 2>/dev/null; then
    echo "WARN: Service still enabled after uninstall"
  else
    echo "Service disabled: OK"
  fi
else
  rm -f /usr/local/sbin/network-flow-monitor-agent
  echo "Binary removed"
fi

# Clean up cgroup mount
umount /mnt/cgroup-nfm 2>/dev/null || true
rmdir /mnt/cgroup-nfm 2>/dev/null || true

echo "Cleanup complete"
