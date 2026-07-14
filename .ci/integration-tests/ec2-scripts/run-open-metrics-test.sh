#!/bin/bash
set -o errexit
set -o pipefail
set -o nounset

# Starts the agent with open-metrics enabled and validates the Prometheus endpoint.

echo "=== Starting agent with open-metrics and running validation ==="

export PATH="$PATH:/usr/sbin:/sbin:/usr/local/sbin"

# Raise RLIMIT_MEMLOCK for BPF map creation on kernels < 5.11
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

# Start agent with open-metrics enabled
LOG_FILE=/tmp/nfm-test/agent-openmetrics.log
mkdir -p /tmp/nfm-test

RUST_LOG=info $AGENT_BIN \
  --cgroup /mnt/cgroup-nfm \
  --publish-reports off \
  --open-metrics on \
  --open-metrics-port 9090 \
  --open-metrics-address 127.0.0.1 > "$LOG_FILE" 2>&1 &
AGENT_PID=$!

sleep 3
if ! kill -0 $AGENT_PID 2>/dev/null; then
  echo "FATAL: Agent failed to start"
  cat "$LOG_FILE"
  exit 1
fi
echo "Agent started (PID $AGENT_PID)"

# Wait for metrics endpoint to be ready
echo "Waiting for metrics endpoint..."
for i in $(seq 1 10); do
  if curl -s http://127.0.0.1:9090/metrics > /dev/null 2>&1; then
    echo "Metrics endpoint ready after ${i}s"
    break
  fi
  if [ $i -eq 10 ]; then
    echo "FATAL: Metrics endpoint not ready after 10s"
    cat "$LOG_FILE"
    kill $AGENT_PID 2>/dev/null || true
    exit 1
  fi
  sleep 1
done

# Wait for first scrape cycle to populate metrics
sleep 5

# Fetch metrics
METRICS=$(curl -s http://127.0.0.1:9090/metrics)
PASS=0
FAIL=0

check() {
  local desc="$1"
  local result="$2"
  if [ "$result" = "true" ]; then
    echo "  PASS: $desc"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $desc"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo "=== Validating metrics endpoint ==="

# Check metrics endpoint returns content
check "Metrics endpoint returns data" \
  "$([ -n "$METRICS" ] && echo true || echo false)"

# System metrics
for metric in bw_in_allowance_exceeded bw_out_allowance_exceeded pps_allowance_exceeded conntrack_allowance_exceeded linklocal_allowance_exceeded; do
  check "System metric '${metric}' present" \
    "$(echo "$METRICS" | grep -q "^${metric}" && echo true || echo false)"
done

# Interface metrics
for metric in ingress_packets ingress_bytes egress_packets egress_bytes; do
  check "Interface metric '${metric}' present" \
    "$(echo "$METRICS" | grep -q "^${metric}" && echo true || echo false)"
done

# Label: instance_id is not "unknown" (on EC2 it should resolve from IMDS)
check "instance_id label resolved from IMDS" \
  "$(echo "$METRICS" | grep -q 'instance_id="i-' && echo true || echo false)"

# Label: iface contains a physical interface name
check "iface label present" \
  "$(echo "$METRICS" | grep -qP 'iface="(eth|ens|enp)' && echo true || echo false)"

# Label: eni contains real ENI ID
check "eni label resolved from IMDS" \
  "$(echo "$METRICS" | grep -q 'eni="eni-' && echo true || echo false)"

# Prometheus format: HELP and TYPE annotations
check "Prometheus HELP annotations present" \
  "$(echo "$METRICS" | grep -q '# HELP' && echo true || echo false)"

check "Prometheus TYPE annotations present" \
  "$(echo "$METRICS" | grep -q '# TYPE' && echo true || echo false)"

# Stop agent
kill $AGENT_PID 2>/dev/null || true
wait $AGENT_PID 2>/dev/null || true

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="

if [ $FAIL -gt 0 ]; then
  echo ""
  echo "=== Agent log (last 30 lines) ==="
  tail -30 "$LOG_FILE" || true
  echo ""
  echo "=== Metrics output sample ==="
  echo "$METRICS" | head -40
  exit 1
fi

echo "All open-metrics checks passed."
exit 0
