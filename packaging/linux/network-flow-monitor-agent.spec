Name:       network-flow-monitor-agent
Summary:    Network Flow Monitor Agent
Release:    1
Version:    %AGENT_VERSION
Requires:   /usr/sbin/setcap, bash

Group:      Amazon/Tools
License:    Apache License, Version 2.0
URL:        https://github.com/aws/network-flow-monitor-agent

Packager:   Amazon Web Services, Inc. <http://aws.amazon.com>
Vendor:     Amazon Web Services, Inc

# Define Macros
%define _build_id_links none
%define PKG_ROOT_DIR /opt/aws/network-flow-monitor
%define NFM_CGROUP_DIR /mnt/cgroup-nfm
%define PACKAGE_COMMAND "$1"
%define MIN_KERNEL_VERSION 5.8
%define AGENT_LOG_DESCRIPTION "Network Flow Monitor Agent %{AGENT_VERSION}"

%define NFM_USER networkflowmonitor
%define NFM_GROUP networkflowmonitor-group

%description
Installs Network Flow Monitor Agent

#### Pre-install scripts
%pre
set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

HOST_KERNEL_VERSION=$(uname -r | cut -d. -f1,2)

# Check kernel version
function version { echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'; }
if [ $(version $HOST_KERNEL_VERSION) -lt $(version %MIN_KERNEL_VERSION) ]; then
    echo "Error: This package requires Linux kernel" %MIN_KERNEL_VERSION "or later. Found $HOST_KERNEL_VERSION"
    exit 1
fi

# Create system user and group
getent group %{NFM_GROUP} >/dev/null || groupadd -r %{NFM_GROUP}
getent passwd %{NFM_USER} >/dev/null || useradd -r -g %{NFM_GROUP} -d %{PKG_ROOT_DIR} -s /sbin/nologin %{NFM_USER}

#### Install scripts
%install
mkdir -p %{buildroot}%{PKG_ROOT_DIR}
mkdir -p %{_topdir}/RPMS
mkdir -p %{_topdir}/BUILD
mkdir -p %{buildroot}/usr/lib/systemd/system
mkdir %{buildroot}%{PKG_ROOT_DIR}/etc
cp %{_sourcedir}/packaging/linux/network-flow-monitor.ini %{buildroot}%{PKG_ROOT_DIR}/etc/
cp %{_sourcedir}/packaging/linux/network-flow-monitor.service %{buildroot}/usr/lib/systemd/system/
cp %{_sourcedir}/packaging/linux/network-flow-monitor-start %{buildroot}%{PKG_ROOT_DIR}/
cp %{_sourcedir}/NOTICE %{buildroot}%{PKG_ROOT_DIR}/
cp %{_sourcedir}/LICENSE %{buildroot}%{PKG_ROOT_DIR}/
cp %{_sourcedir}/target/release/network-flow-monitor-agent %{buildroot}%{PKG_ROOT_DIR}/network-flow-monitor-agent


#### Post-install scripts
%post
# Dual RPM/DEB helper: returns 0 (true) if this is an upgrade (not fresh install)
# RPM: $1 = 1 for fresh install, $1 >= 2 for upgrade
# DEB: $1 = "configure" with $2 = old-version for upgrade
# https://docs.fedoraproject.org/en-US/packaging-guidelines/Scriptlets/
is_upgrade() {
    case "$1" in
        configure)
            [ -n "${2:-}" ] && return 0
            return 1
            ;;
        *[!0-9]*) return 1 ;;
        *) [ "$1" -ge 2 ] ;;
    esac
}

## Capabilities
# Giving the agent capabilities so that we can perform e/BPF actions
# Try with cap_bpf name first, fallback to numeric to support older setcap versions
if ! setcap cap_sys_admin,cap_bpf=eip %{PKG_ROOT_DIR}/network-flow-monitor-agent 2>/dev/null; then
    setcap cap_sys_admin,39=eip %{PKG_ROOT_DIR}/network-flow-monitor-agent
fi

# Only create mount points on fresh install or if the mountpoint doesn't exist
if ! is_upgrade %PACKAGE_COMMAND "${2:-}" || ! mountpoint -q %{NFM_CGROUP_DIR}; then
    echo "creating cgroupv2 mount point"
    mkdir -p %{NFM_CGROUP_DIR}
    chown %{NFM_USER}:%{NFM_GROUP} %{NFM_CGROUP_DIR}
    mount -t cgroup2 networkflowmonitor-cgroup %{NFM_CGROUP_DIR}
    echo "networkflowmonitor-cgroup %{NFM_CGROUP_DIR} cgroup2 defaults 0 0" >> /etc/fstab
fi

## Service start + enable on startup
if is_upgrade %PACKAGE_COMMAND "${2:-}"; then
    echo "Restarting network-flow-monitor-agent"
    systemctl try-restart network-flow-monitor.service
else
    systemctl start network-flow-monitor.service
fi
systemctl enable network-flow-monitor.service

echo "%{AGENT_LOG_DESCRIPTION} installed successfully."

### Pre-Uninstall Scripts
%preun
# Dual RPM/DEB helper: returns 0 (true) if this is a full removal (not upgrade)
# RPM passes numeric $1: 0 = removal, >= 1 = upgrade
# DEB passes string $1: "remove", "purge" = removal; "upgrade" = upgrade
is_removal() {
    case "$1" in
        remove|purge|0) return 0 ;;
        *) return 1 ;;
    esac
}

if is_removal %PACKAGE_COMMAND; then
    systemctl --no-reload disable network-flow-monitor.service > /dev/null 2>&1 || :
    systemctl stop network-flow-monitor.service > /dev/null 2>&1 || :

    echo "removing cgroupv2 mount point"
    if mountpoint -q %{NFM_CGROUP_DIR}; then
        umount %{NFM_CGROUP_DIR}
        sed -i.bak "\@^networkflowmonitor-cgroup@d" /etc/fstab
    fi
    rm -rf %{NFM_CGROUP_DIR}
fi
echo "%{AGENT_LOG_DESCRIPTION} uninstalled successfully."


### Post-Uninstall Scripts
%postun
# Dual RPM/DEB helper: returns 0 (true) if this is a full removal (not upgrade)
is_removal() {
    case "$1" in
        remove|purge|0) return 0 ;;
        *) return 1 ;;
    esac
}

systemctl daemon-reload > /dev/null 2>&1 || :

if is_removal %PACKAGE_COMMAND; then
    userdel %{NFM_USER} 2>/dev/null || :
    groupdel %{NFM_GROUP} 2>/dev/null || :
else
    # Package upgrade: restart to pick up the new binary
    systemctl try-restart network-flow-monitor.service > /dev/null 2>&1 || :
fi

%files
%defattr(-,%{NFM_USER},%{NFM_GROUP})
%{PKG_ROOT_DIR}/
/usr/lib/systemd/system/network-flow-monitor.service

%clean
# rpmbuild deletes $buildroot after building, specifying clean section to make sure it is not deleted
