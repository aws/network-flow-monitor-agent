#!/bin/bash
set -o errexit
set -o pipefail
set -o nounset

# Starts the agent in test mode and runs the integration test suite.

echo "=== Starting agent and running integration test ==="

export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"

# Diagnostics: BPF/security settings
echo "=== BPF Diagnostics ==="
echo "Kernel: $(uname -r)"
sysctl kernel.unprivileged_bpf_disabled 2>/dev/null || echo "sysctl not available"
cat /sys/kernel/security/lockdown 2>/dev/null || echo "No lockdown file"
echo "Running as: $(id)"
echo "========================"

# Raise RLIMIT_MEMLOCK for BPF map creation on kernels < 5.11
# (kernels >= 5.11 use cgroup-based memory accounting and don't need this)
ulimit -l unlimited

# Set up cgroup
mkdir -p /mnt/cgroup-nfm
if ! mountpoint -q /mnt/cgroup-nfm; then
  mount -t cgroup2 none /mnt/cgroup-nfm
fi

# Determine agent binary location
if [ -f /opt/aws/network-flow-monitor/network-flow-monitor-agent ]; then
  AGENT_BIN=/opt/aws/network-flow-monitor/network-flow-monitor-agent
elif [ -f /usr/local/sbin/network-flow-monitor-agent ]; then
  AGENT_BIN=/usr/local/sbin/network-flow-monitor-agent
else
  AGENT_BIN=/tmp/nfm-build/target/release/network-flow-monitor-agent
fi
echo "Using agent: $AGENT_BIN"

# Start agent in test mode (log reports locally, don't publish to endpoint)
LOG_FILE=/tmp/nfm-test/agent.log
mkdir -p /tmp/nfm-test
PUBLISH_SECS=5

RUST_LOG=debug $AGENT_BIN \
  --cgroup /mnt/cgroup-nfm \
  --publish-reports off \
  --log-reports on \
  --notrack-secs 10 \
  --publish-secs $PUBLISH_SECS > "$LOG_FILE" 2>&1 &
AGENT_PID=$!

sleep 2
if ! kill -0 $AGENT_PID 2>/dev/null; then
  echo "FATAL: Agent failed to start"
  cat "$LOG_FILE"
  exit 1
fi
echo "Agent started (PID $AGENT_PID)"

# Prepare and run test
mkdir -p /tmp/nfm-test/test-scripts
cp /tmp/nfm-build/test-data/integration-test-01-basic /tmp/nfm-test/test-scripts/
cp /tmp/nfm-build/test-data/tools/test_common.py /tmp/nfm-test/test-scripts/
chmod +x /tmp/nfm-test/test-scripts/*

cd /tmp/nfm-test/test-scripts
python3 integration-test-01-basic --log-path "$LOG_FILE" --publish-secs $PUBLISH_SECS
TEST_RESULT=$?

# Stop agent
kill $AGENT_PID 2>/dev/null || true
wait $AGENT_PID 2>/dev/null || true

if [ $TEST_RESULT -ne 0 ]; then
  echo "Agent log (last 50 lines):"
  tail -50 "$LOG_FILE" || true
fi

exit $TEST_RESULT
