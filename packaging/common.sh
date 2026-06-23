#!/usr/bin/env bash
# Shared build logic for all NFM Agent RPM packaging scripts.
# Sourced by individual create_rpm scripts — not executed directly.

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Determine target architecture
TARGET_ARCH="${1:-$(uname -p)}"

if [ -z "$TARGET_ARCH" ]; then
    echo "Error: Architecture name must be provided or detectable" >&2
    exit 1
fi

if [[ "$TARGET_ARCH" != "x86_64" && "$TARGET_ARCH" != "aarch64" ]]; then
    echo "Error: Unsupported architecture: $TARGET_ARCH (expected x86_64 or aarch64)" >&2
    exit 1
fi

# Detect NFM Agent version from Cargo.toml
AGENT_VERSION=$(grep '^version' "${REPO_ROOT}/nfm-controller/Cargo.toml" | head -1 | sed 's/.*"\(.*\)"/\1/')
if [ -z "$AGENT_VERSION" ]; then
    echo "Error: Could not extract version from nfm-controller/Cargo.toml" >&2
    exit 1
fi
echo "Detected agent version: $AGENT_VERSION"

# Build Rust binary
(cd "${REPO_ROOT}" && cargo build --release)

OUT_DIR="${REPO_ROOT}/out"
mkdir -p "${OUT_DIR}"
