# Building Network Flow Monitor Agent Packages

This directory contains the infrastructure to compile new Network Flow Monitor Agent release packages.

## Building in Docker

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

## Building locally

Run the RPM build script:
```
    ./packaging/linux/create_rpm.sh
```
The script will create an `out` directory in the root of the Git repository containing the build artifacts.
