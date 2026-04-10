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

Some unit tests need privileges to run:
```
sudo -E cargo test --features privileged
```
### Distributions
You can download the official release from our permanent URLs. For more information, refer to [link](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-NetworkFlowMonitor-agents-download-agent-commandline.html)

## Versioning

This project follows [Semantic Versioning](https://semver.org/) with tags in the format `vX.Y.Z`:

- `X` (major): Incompatible changes (e.g., breaking config format, removed features)
- `Y` (minor): New functionality in a backward-compatible manner (e.g., new metrics, new CLI flags)
- `Z` (patch): Backward-compatible bug fixes and minor improvements

The agent version is defined in `nfm-controller/Cargo.toml` and used by the Rust binary at runtime.

### Release Tags

When the version in `Cargo.toml` is updated on `main`, a GitHub Action automatically creates a `vX.Y.Z` tag.
EKS releases use separate `vX.Y.Z-eksbuild.N` tags that may point to different commits
(e.g., helm chart changes without agent code changes).

### Bumping the Version

1. Update the version in `nfm-controller/Cargo.toml`
2. Merge to `main`
3. The `tag-release` workflow creates the tag automatically

### Version Sync

The following files are kept in sync automatically via the `version-sync` workflow:

| File | Field | Updated by |
|---|---|---|
| `nfm-controller/Cargo.toml` | `version` | Developer (source of truth) |
| `charts/.../Chart.yaml` | `version` | Auto-synced from Cargo.toml |
| `charts/.../values.yaml` | `image.tag` | Auto-synced or manual bump |

When `Cargo.toml` version changes in a PR:
- `Chart.yaml` version is updated automatically
- `values.yaml` tag is reset to `vX.Y.Z-eksbuild.1`

When only `values.yaml` tag changes (e.g., helm chart fix):
- The `eksbuild` number must increment by exactly 1
- The base version must match `Cargo.toml`

## License

This project is licensed under the Apache 2.0 License.
