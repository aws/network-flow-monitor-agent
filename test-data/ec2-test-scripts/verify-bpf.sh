#!/bin/bash
set -o nounset

# Verifies that BPF prerequisites are met on this kernel.
# Non-fatal — reports findings but does not fail the test.

echo "=== Verifying BPF prerequisites ==="
echo "Kernel: $(uname -r)"

KERNEL_CONFIG="/boot/config-$(uname -r)"
if [ -f "$KERNEL_CONFIG" ]; then
  grep CONFIG_BPF_SYSCALL "$KERNEL_CONFIG" || echo "WARN: CONFIG_BPF_SYSCALL not found"
  grep CONFIG_CGROUP_BPF "$KERNEL_CONFIG" || echo "WARN: CONFIG_CGROUP_BPF not found"
else
  echo "Kernel config not found at $KERNEL_CONFIG (common on some distros), skipping"
fi
