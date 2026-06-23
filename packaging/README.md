# Building Network Flow Monitor Agent Packages

This directory contains the infrastructure to compile new Network Flow Monitor Agent release packages.

## Standalone RPM (`linux/`)

Builds the standard NFM Agent RPM that installs as a systemd service.

### Building in Docker

First, build the Docker image:
```
   docker build -t nfm-agent-builder -f packaging/linux/Dockerfile .
```

Now run the Docker container. It expects the root of this Git repository to be mounted at `/nfm` in the container, so fill in the `source` of the bind mount appropriately:
```
   docker run --rm --mount type=bind,source=/path/to/network-flow-monitor-agent-git-repo/,target=/nfm nfm-agent-builder
```

The container will create an `out` directory in the root of the Git repository containing the build artifacts.
```
$ ls out/*.rpm
out/network-flow-monitor-agent.rpm
```

### Building locally

Run the RPM build script:
```
    ./packaging/linux/create_rpm.sh
```
The script will create an `out` directory in the root of the Git repository containing the build artifacts.

## SSM v4 Supervised Extension RPM (`ssm-extension/`)

Builds an RPM that installs the NFM Agent as a supervised extension for the AWS SSM Agent v4. The SSM Agent manages the full lifecycle (install, configure, start, stop, health monitoring, uninstall) via shell scripts.

### Prerequisites

The standalone NFM Agent RPM must be built first (see above). The extension RPM bundles it as an artifact.

### Building

```
    ./packaging/ssm-extension/create_extension_rpm.sh
```

Output: `out/aws-ssm-networkflowmonitor.rpm`

### Installation

```bash
# SSM v4 Agent must be installed first

# Then install the extension
sudo rpm -i aws-ssm-networkflowmonitor.rpm
```

See `ssm-extension/README.md` for full details on directory layout, lifecycle scripts, and credential handling.
