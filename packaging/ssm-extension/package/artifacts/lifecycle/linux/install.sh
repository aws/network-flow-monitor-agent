#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

echo "Installing NFM Agent extension..."
echo "Extension ID: ${EXTENSION_ID}"
echo "Extension Dir: ${EXTENSION_DIR}"
echo "Working Dir: ${WORKING_DIR}"

# Step 1: Verify kernel version >= 5.8
if ! check_kernel_version; then
    echo "Error: Kernel version check failed. NFM Agent requires kernel 5.8 or later." >&2
    exit 1
fi

# Step 2: Create WORKING_DIR if it doesn't exist
mkdir -p "${WORKING_DIR}"

# Step 3: Create NFM_Group idempotently
getent group networkflowmonitor-group >/dev/null 2>&1 || groupadd -r networkflowmonitor-group

# Step 4: Create NFM_User idempotently
getent passwd networkflowmonitor >/dev/null 2>&1 || useradd -r -g networkflowmonitor-group -d /opt/aws/network-flow-monitor -s /sbin/nologin networkflowmonitor

# Step 5: Install/upgrade bundled NFM RPM (--noscripts skips NFM RPM's own scriptlets)
rpm -U --noscripts "${EXTENSION_DIR}/artifacts/network-flow-monitor-agent.rpm" 2>&1

# Step 6: Set eBPF capabilities on the NFM Agent binary
if ! setcap cap_sys_admin,cap_bpf=eip /opt/aws/network-flow-monitor/network-flow-monitor-agent 2>/dev/null; then
    setcap cap_sys_admin,39=eip /opt/aws/network-flow-monitor/network-flow-monitor-agent
fi

# Step 7: Create cgroupv2 mount at /mnt/cgroup-nfm if not already mounted
if ! mountpoint -q /mnt/cgroup-nfm 2>/dev/null; then
    mkdir -p /mnt/cgroup-nfm
    chown networkflowmonitor:networkflowmonitor-group /mnt/cgroup-nfm
    mount -t cgroup2 networkflowmonitor-cgroup /mnt/cgroup-nfm
fi

# Step 8: Add fstab entry if not already present
grep -q "networkflowmonitor-cgroup" /etc/fstab 2>/dev/null || \
    echo "networkflowmonitor-cgroup /mnt/cgroup-nfm cgroup2 defaults 0 0" >> /etc/fstab

# Step 9: Disable systemd service to prevent auto-start on boot (Core Agent manages lifecycle)
systemctl disable network-flow-monitor.service 2>/dev/null || true

echo "Installation complete"
exit 0
