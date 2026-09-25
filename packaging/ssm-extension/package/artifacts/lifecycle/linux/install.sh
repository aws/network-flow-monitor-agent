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

# Step 5: Install/upgrade the bundled NFM package. EXTENSION_DIR/artifacts/ only
# ever ships the ONE package format matching this host's package manager (the
# publishing pipeline filters artifacts/ down to a single format per build), so
# pick whichever is actually present rather than assuming rpm.
RPM_PKG="${EXTENSION_DIR}/artifacts/network-flow-monitor-agent.rpm"
DEB_PKG="${EXTENSION_DIR}/artifacts/network-flow-monitor-agent.deb"

if [ -f "${RPM_PKG}" ]; then
    PKG_FORMAT=rpm
elif [ -f "${DEB_PKG}" ]; then
    PKG_FORMAT=deb
else
    echo "Error: no bundled package found at ${RPM_PKG} or ${DEB_PKG}" >&2
    exit 1
fi

NFM_PREINSTALLED=false
INSTALLED_NEW_PKG=false
cleanup() {
    echo "Install failed, cleaning up..." >&2
    if [ "$INSTALLED_NEW_PKG" = true ]; then
        if [ "$PKG_FORMAT" = rpm ]; then
            rpm -e --noscripts network-flow-monitor-agent 2>/dev/null || true
        else
            dpkg --purge network-flow-monitor-agent 2>/dev/null || true
        fi
    fi
}
trap cleanup EXIT

if [ "$PKG_FORMAT" = rpm ]; then
    rpm -q network-flow-monitor-agent >/dev/null 2>&1 && NFM_PREINSTALLED=true

    # Run an rpm install/upgrade, retrying on transaction-lock contention.
    run_rpm() {
        local out rc
        for _ in {1..6}; do
            if out="$(LC_ALL=C rpm "$@" 2>&1)"; then
                [ -n "$out" ] && printf '%s\n' "$out"
                return 0
            fi
            rc=$?
            if printf '%s' "$out" | grep -qE "can't create transaction lock|Resource temporarily unavailable.*\.rpm\.lock|\.rpm\.lock.*Resource temporarily unavailable"; then
                echo "rpm transaction lock held by another process, retrying in 5s..."
                sleep 5
                continue
            fi
            [ -n "$out" ] && printf '%s\n' "$out" >&2
            return "$rc"
        done
        echo "ERROR: rpm transaction lock not released after retries"
        return 1
    }

    # --noscripts skips the bundled RPM's own scriptlets; --replacepkgs makes this
    # idempotent across CADS retries of a partially-failed install; --oldpackage
    # allows the bundled RPM to be older than what's installed (e.g. a rollback).
    run_rpm -U --replacepkgs --oldpackage --noscripts "${RPM_PKG}"
else
    dpkg -s network-flow-monitor-agent >/dev/null 2>&1 && NFM_PREINSTALLED=true

    # Run a dpkg install/upgrade, retrying on dpkg-lock contention -- mirrors
    # run_rpm's retry-on-transaction-lock loop above.
    run_dpkg() {
        local out rc
        for _ in {1..6}; do
            if out="$(LC_ALL=C dpkg "$@" 2>&1)"; then
                [ -n "$out" ] && printf '%s\n' "$out"
                return 0
            fi
            rc=$?
            if printf '%s' "$out" | grep -qiE "dpkg.*lock|resource temporarily unavailable"; then
                echo "dpkg lock held by another process, retrying in 5s..."
                sleep 5
                continue
            fi
            [ -n "$out" ] && printf '%s\n' "$out" >&2
            return "$rc"
        done
        echo "ERROR: dpkg lock not released after retries"
        return 1
    }

    # dpkg -i always installs/overwrites regardless of version, so there is no
    # --oldpackage equivalent to pass. NOTE: unlike rpm's --noscripts above, this
    # does NOT suppress the bundled .deb's own maintainer scripts -- confirm the
    # built .deb's preinst/postinst are no-ops (or add --no-triggers /
    # DPKG_MAINTSCRIPT_* handling here) before relying on this in production.
    run_dpkg -i "${DEB_PKG}"
fi
[ "$NFM_PREINSTALLED" = true ] || INSTALLED_NEW_PKG=true

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

# Step 9: Disable systemd service to prevent auto-start on boot (SSM Agent v4 manages lifecycle)
systemctl disable network-flow-monitor.service 2>/dev/null || true

trap - EXIT
echo "Installation complete"
exit 0
