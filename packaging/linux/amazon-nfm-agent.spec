Name:       amazon-nfm-agent
Summary:    Network Flow Monitor Agent
Release:    %release
Version:    0.1
Requires:   bash

Group:      Amazon/Tools
License:    Apache License, Version 2.0
URL:        https://github.com/aws/network-flow-monitor-agent

Packager:   Amazon.com, Inc. <http://aws.amazon.com>
Vendor:     Amazon.com

# Define Macros
%define _build_id_links none
%define PKG_ROOT_DIR /opt/aws/network-flow-monitor
%define NEFMO_CGROUP_DIR /mnt/cgroupnefmon
%define PACKAGES_LEFT "$1"
%define PACKAGE_COMMAND "$1"
%define MIN_KERNEL_VERSION 5.8
%define AGENT_LOG_DESCRIPTION "Network Flow Monitor Agent %{release}"

%define NEFMON_USER networkflowmonitor
%define NEFMON_GROUP networkflowmonitor-group

%description
Installs NetworkFlowMonitorAgent

#### Pre-install scripts
%pre
set -o errexit # Exit if a command fails
set -o nounset # Exit if an undefined variable is used
set -o pipefail # Exit if a command in a pipeline fails

HOST_KERNEL_VERSION=$(uname -r | cut -d. -f1,2)

# Check kernel version
function version { echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'; }
if [ $(version $HOST_KERNEL_VERSION) -lt $(version %MIN_KERNEL_VERSION) ]; then
    echo "Error: This package requires Linux kernel" %MIN_KERNEL_VERSION "or later. Found $HOST_KERNEL_VERSION"
    exit 1
fi

# Existing pre-install scripts...
getent group %{NEFMON_GROUP} >/dev/null || groupadd -r %{NEFMON_GROUP}
getent passwd %{NEFMON_USER} >/dev/null || useradd -r -g %{NEFMON_GROUP} -d %{PKG_ROOT_DIR} -s /sbin/nologin %{NEFMON_USER}

getent group %{NEFMON_GROUP} >/dev/null || groupadd -r %{NEFMON_GROUP}
getent passwd %{NEFMON_USER} >/dev/null || useradd -r -g %{NEFMON_GROUP} -d %{PKG_ROOT_DIR} -s /sbin/nologin %{NEFMON_USER}

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
%systemd_post network-flow-monitor.service

## Capabilities
# Giving the agent capabilities so that we can perform e/BPF actions
setcap cap_sys_admin,cap_bpf=eip %{PKG_ROOT_DIR}/network-flow-monitor-agent

# Only create mount points on install or if the mountpoint doesn't exists
if [ %PACKAGES_LEFT = 1 ] || ! mountpoint -q %{NEFMO_CGROUP_DIR}; then
    echo "creating cgroupv2 mount point"
    ## CGROUP
    mkdir -p %{NEFMO_CGROUP_DIR}
    chown %{NEFMON_USER}:%{NEFMON_GROUP} %{NEFMO_CGROUP_DIR}
    mount -t cgroup2 networkflowmonitor-cgroup %{NEFMO_CGROUP_DIR}
    echo "networkflowmonitor-cgroup %{NEFMO_CGROUP_DIR} cgroup2 defaults 0 0" >> /etc/fstab
fi

## Service start + enable on startup
systemctl start network-flow-monitor.service
systemctl enable network-flow-monitor.service

echo "%{AGENT_LOG_DESCRIPTION} installed successfully."

### Pre-Uninstall Scripts
%preun
%systemd_preun network-flow-monitor.service

# Only remove mount points on uninstall
if [ %PACKAGES_LEFT = 0 ] || [ %PACKAGE_COMMAND = "remove" ]; then
    echo "removing cgroupv2 mount point"
    ## CGROUP
    if mountpoint -q %{NEFMO_CGROUP_DIR}; then
        umount %{NEFMO_CGROUP_DIR}
        sed -i.bak "\@^networkflowmonitor-cgroup@d" /etc/fstab
    fi
    rm -rf %{NEFMO_CGROUP_DIR}
fi
echo "%{AGENT_LOG_DESCRIPTION} uninstalled successfully."


### Post-Uninstall Scripts
%postun
if [ %PACKAGES_LEFT = 0 ] || [ %PACKAGE_COMMAND = "remove" ]; then
    userdel %{NEFMON_USER}
    groupdel %{NEFMON_GROUP}
fi

%files
%defattr(-,%{NEFMON_USER},%{NEFMON_GROUP})
%{PKG_ROOT_DIR}/
/usr/lib/systemd/system/network-flow-monitor.service

%clean
# rpmbuild deletes $buildroot after building, specifying clean section to make sure it is not deleted
