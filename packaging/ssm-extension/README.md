# NFM Agent — SSM v4 Supervised Extension RPM

This directory builds an RPM that installs the Network Flow Monitor Agent as a **supervised extension** for the AWS SSM Agent v4. The SSM Agent manages the NFM Agent lifecycle (install, configure, start, stop, health monitoring, uninstall) via shell scripts.

## Prerequisites

1. The standalone NFM Agent RPM must be built first:
   ```
   ./packaging/linux/create_rpm.sh
   ```
   This produces `out/network-flow-monitor-agent.rpm`.

2. The AWS SSM Agent v4 RPM must be installed on the target host before this extension RPM.

## Building the Extension RPM

```bash
./packaging/ssm-extension/create_extension_rpm.sh
```

Output: `out/aws-ssm-networkflowmonitor.rpm`

The script:
- Detects the agent version from `nfm-controller/Cargo.toml`
- Bundles the pre-built NFM RPM as an artifact inside the extension
- Produces a single RPM that installs all extension files

## Installation

```bash
# Install SSM Agent v4 first
sudo rpm -i aws-core-agent.rpm

# Install the NFM extension
sudo rpm -i aws-ssm-networkflowmonitor.rpm
```

The extension RPM's `%post` script triggers the SSM Agent to drive the lifecycle automatically.

## Directory Layout (on target host)

| Path | Contents |
|------|----------|
| `/opt/amazon/aws-core-agent/aws.ssm.networkflowmonitor/manifest.json` | Extension manifest |
| `/opt/amazon/aws-core-agent/aws.ssm.networkflowmonitor/scripts/` | Lifecycle scripts |
| `/opt/amazon/aws-core-agent/aws.ssm.networkflowmonitor/artifacts/` | Bundled NFM RPM |
| `/etc/amazon/aws-core-agent/aws.ssm.networkflowmonitor.json` | Extension config |
| `/var/opt/amazon/aws-core-agent/aws.ssm.networkflowmonitor/` | Working directory |
| `/var/log/amazon/aws-core-agent/extensions/aws.ssm.networkflowmonitor/` | Logs |

## Lifecycle Scripts

| Script | Purpose |
|--------|---------|
| `install.sh` | Installs NFM RPM (--noscripts), creates user/group, sets capabilities, mounts cgroupv2 |
| `configure.sh` | Maps SSM Agent config to NFM INI format, sets up credentials per identity type |
| `start.sh` | Starts the `network-flow-monitor.service` systemd unit |
| `stop.sh` | Stops the systemd service |
| `health_check.sh` | Checks `systemctl is-active` for the service |
| `status.sh` | Returns JSON with service state, start time, and timestamp |
| `uninstall.sh` | Full teardown: stops service, removes RPM, cleans cgroup/user/group |
