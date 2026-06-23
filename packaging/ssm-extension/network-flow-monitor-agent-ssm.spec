Name:       aws-ssm-networkflowmonitor
Summary:    Network Flow Monitor Agent — SSM v4 Supervised Extension
Release:    1
Version:    %{AGENT_VERSION}

Group:      Amazon/Tools
License:    Apache License, Version 2.0
URL:        https://github.com/aws/network-flow-monitor-agent

Packager:   Amazon Web Services, Inc. <http://aws.amazon.com>
Vendor:     Amazon Web Services, Inc

%define _build_id_links none
%define NAMESPACE aws.ssm.networkflowmonitor
%define EXTENSION_BASE /opt/amazon/aws-core-agent
%define EXTENSION_DIR %{EXTENSION_BASE}/%{NAMESPACE}
%define CONFIG_DIR /etc/amazon/aws-core-agent
%define WORKING_DIR /var/opt/amazon/aws-core-agent/%{NAMESPACE}
%define LOG_DIR /var/log/amazon/aws-core-agent/extensions/%{NAMESPACE}

%description
Installs the Network Flow Monitor Agent as a supervised extension for the
AWS SSM Agent v4. This RPM places the manifest, lifecycle scripts,
placeholder binary, bundled NFM Agent RPM, and extension configuration on
disk. The SSM Agent then drives the lifecycle (install → configure → start).

%pre
# Verify the SSM Agent v4 binary exists and is executable
if [ ! -x %{EXTENSION_BASE}/aws-core-agent ]; then
    echo "Error: AWS SSM Agent v4 not found at %{EXTENSION_BASE}/aws-core-agent" >&2
    echo "Install the SSM Agent v4 RPM first: sudo rpm -i aws-core-agent.rpm" >&2
    exit 1
fi

%install
# Extension directory structure
mkdir -p %{buildroot}%{EXTENSION_DIR}
mkdir -p %{buildroot}%{EXTENSION_DIR}/scripts
mkdir -p %{buildroot}%{EXTENSION_DIR}/artifacts
mkdir -p %{buildroot}%{CONFIG_DIR}
mkdir -p %{buildroot}%{WORKING_DIR}
mkdir -p %{buildroot}%{LOG_DIR}

# Manifest
cp %{_sourcedir}/package/manifest.json %{buildroot}%{EXTENSION_DIR}/manifest.json

# Placeholder binary
touch %{buildroot}%{EXTENSION_DIR}/%{NAMESPACE}
chmod 755 %{buildroot}%{EXTENSION_DIR}/%{NAMESPACE}

# Lifecycle scripts
cp %{_sourcedir}/package/artifacts/lifecycle/linux/common.sh      %{buildroot}%{EXTENSION_DIR}/scripts/
cp %{_sourcedir}/package/artifacts/lifecycle/linux/install.sh      %{buildroot}%{EXTENSION_DIR}/scripts/
cp %{_sourcedir}/package/artifacts/lifecycle/linux/configure.sh    %{buildroot}%{EXTENSION_DIR}/scripts/
cp %{_sourcedir}/package/artifacts/lifecycle/linux/start.sh        %{buildroot}%{EXTENSION_DIR}/scripts/
cp %{_sourcedir}/package/artifacts/lifecycle/linux/stop.sh         %{buildroot}%{EXTENSION_DIR}/scripts/
cp %{_sourcedir}/package/artifacts/lifecycle/linux/health_check.sh %{buildroot}%{EXTENSION_DIR}/scripts/
cp %{_sourcedir}/package/artifacts/lifecycle/linux/status.sh       %{buildroot}%{EXTENSION_DIR}/scripts/
cp %{_sourcedir}/package/artifacts/lifecycle/linux/uninstall.sh    %{buildroot}%{EXTENSION_DIR}/scripts/

# Bundled NFM Agent RPM
cp %{_sourcedir}/artifacts/network-flow-monitor-agent.rpm %{buildroot}%{EXTENSION_DIR}/artifacts/

# Extension configuration
cp %{_sourcedir}/package/artifacts/config/config.json %{buildroot}%{CONFIG_DIR}/%{NAMESPACE}.json

%post
# Create working and log directories
mkdir -p %{WORKING_DIR}
mkdir -p %{LOG_DIR}

# Trigger the SSM Agent v4 lifecycle: install.sh -> configure.sh -> start.sh
%{EXTENSION_BASE}/aws-core-agent start-extension --namespace %{NAMESPACE} 2>/dev/null || true

%preun
# On full removal ($1 -eq 0), stop the extension
if [ "$1" -eq 0 ]; then
    %{EXTENSION_BASE}/aws-core-agent stop-extension --namespace %{NAMESPACE} || true
fi

%files
# Manifest (644)
%attr(644,root,root) %{EXTENSION_DIR}/manifest.json

# Placeholder binary (755)
%attr(755,root,root) %{EXTENSION_DIR}/%{NAMESPACE}

# Lifecycle scripts (755)
%attr(755,root,root) %{EXTENSION_DIR}/scripts/common.sh
%attr(755,root,root) %{EXTENSION_DIR}/scripts/install.sh
%attr(755,root,root) %{EXTENSION_DIR}/scripts/configure.sh
%attr(755,root,root) %{EXTENSION_DIR}/scripts/start.sh
%attr(755,root,root) %{EXTENSION_DIR}/scripts/stop.sh
%attr(755,root,root) %{EXTENSION_DIR}/scripts/health_check.sh
%attr(755,root,root) %{EXTENSION_DIR}/scripts/status.sh
%attr(755,root,root) %{EXTENSION_DIR}/scripts/uninstall.sh

# Bundled NFM RPM
%{EXTENSION_DIR}/artifacts/network-flow-monitor-agent.rpm

# Extension configuration (644)
%attr(644,root,root) %config(noreplace) %{CONFIG_DIR}/%{NAMESPACE}.json

# Working directory
%dir %{WORKING_DIR}

# Log directory
%dir %{LOG_DIR}

%clean
# rpmbuild deletes $buildroot after building, specifying clean section to prevent that
