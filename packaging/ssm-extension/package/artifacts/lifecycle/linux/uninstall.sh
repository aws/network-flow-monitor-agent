#!/bin/bash
# Best-effort cleanup: each step logs failures but continues. Always exits 0.

echo "Uninstalling NFM Agent extension..."
echo "Extension ID: ${EXTENSION_ID}"

# Step 1: Stop the systemd service
systemctl stop network-flow-monitor.service 2>/dev/null || echo "Warning: Failed to stop service" >&2

# Step 2: Disable the systemd service
systemctl disable network-flow-monitor.service 2>/dev/null || echo "Warning: Failed to disable service" >&2

# Step 3: Remove the NFM RPM
rpm -e --noscripts network-flow-monitor-agent 2>/dev/null || echo "Warning: Failed to remove NFM RPM (may not be installed)" >&2

# Step 4: Unmount cgroupv2
if mountpoint -q /mnt/cgroup-nfm 2>/dev/null; then
    umount /mnt/cgroup-nfm 2>/dev/null || echo "Warning: Failed to unmount /mnt/cgroup-nfm" >&2
fi

# Step 5: Remove fstab entry
sed -i '\@^networkflowmonitor-cgroup@d' /etc/fstab 2>/dev/null || echo "Warning: Failed to remove fstab entry" >&2

# Step 6: Remove mount directory
rm -rf /mnt/cgroup-nfm 2>/dev/null || echo "Warning: Failed to remove /mnt/cgroup-nfm" >&2

# Step 7: Remove systemd drop-in override
rm -rf /etc/systemd/system/network-flow-monitor.service.d 2>/dev/null || echo "Warning: Failed to remove systemd drop-in" >&2

# Step 8: Reload systemd daemon
systemctl daemon-reload 2>/dev/null || echo "Warning: Failed to reload systemd daemon" >&2

# Step 9: Remove NFM user
userdel networkflowmonitor 2>/dev/null || echo "Warning: Failed to remove user networkflowmonitor" >&2

# Step 10: Remove NFM group
groupdel networkflowmonitor-group 2>/dev/null || echo "Warning: Failed to remove group networkflowmonitor-group" >&2

# Step 11: Clean WORKING_DIR
rm -rf "${WORKING_DIR:?}/"* 2>/dev/null || echo "Warning: Failed to clean WORKING_DIR" >&2

echo "Uninstallation complete"
exit 0
