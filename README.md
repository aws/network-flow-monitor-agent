# Network Flow Monitor Agent

[![CI](https://github.com/aws/network-flow-monitor-agent/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/aws/network-flow-monitor-agent/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/github/aws/network-flow-monitor-agent/graph/badge.svg?token=T4XUR6NZRM)](https://codecov.io/github/aws/network-flow-monitor-agent)

This is an on-host agent that passively collects performance statistics related
to various communication protocols of interest, beginning with TCP.  The
statistics can be published in an OpenTelemetry format to an ingestion
endpoint.

This application runs on Linux kernel version 5.8 and newer.

## Installation

> [!TIP]
> [Instructions are
> available](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-NetworkFlowMonitor-agents.html)
> to deploy across a fleet of EC2 instances or EKS clusters and integrate with
> Amazon CloudWatch Network Flow Monitor.

### Building

> [!NOTE]
> Before proceeding, make sure you have a C compiler and [Rust development
> tools](https://www.rust-lang.org/tools/install) available on your system.

Build the application using the command:

```bash
cargo build --release
```

### Running

> [!NOTE]
> Before starting the application, make sure you've created a cgroup.  This
> usually requires root priveleges or the `CAP_SYS_ADMIN` capability.
>
> ```bash
> mkdir /mnt/cgroup-nfm
> mount -t cgroup2 none /mnt/cgroup-nfm
> ```

To run the application with statistics printed to stdout, use the following
command.  Run this as root or with the `CAP_BPF` capability.

```bash
target/release/network-flow-monitor-agent --cgroup /mnt/cgroup-nfm \
   --publish-reports off --log-reports on
```

### Testing

Run GitHub actions locally using the [act](https://nektosact.com/) CLI:

```bash
act workflow_dispatch --privileged
```

Run only integration tests by building and running the test suite's docker container:

```bash
docker build -t integration-tests -f test-data/Dockerfile.test .
docker run --privileged -t integration-tests
```

## License

This project is licensed under the Apache 2.0 License.
