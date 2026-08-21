#!/bin/bash
# Installs bpf-linker via cargo-binstall.
#
# Usage: install-bpf-linker.sh

set -o errexit
set -o pipefail
set -o nounset

curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
cargo binstall bpf-linker --no-confirm
