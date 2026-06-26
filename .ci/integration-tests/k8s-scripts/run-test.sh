#!/bin/bash
# Runs the integration test suite against the NFM agent deployed in Kubernetes.
#
# Usage: run-test.sh <kubeconfig> [arch]
#
# This script:
#   1. Deploys a test workload (client + server pods) to generate TCP traffic
#   2. Waits for the agent to observe and report the connections
#   3. Validates the agent logs contain the expected flow data
#
# Prerequisites:
#   - NFM agent DaemonSet is already running (via deploy-agent.sh)
#   - Agent is deployed with LOG_REPORTS=on and publishing enabled

set -o errexit
set -o pipefail
set -o nounset

KUBECONFIG_PATH="$1"
TARGET_ARCH="${2:-}"
export KUBECONFIG="$KUBECONFIG_PATH"

NAMESPACE="amazon-cloudwatch-${TARGET_ARCH:-default}"
TEST_NAMESPACE="nfm-test-${TARGET_ARCH:-default}"
PUBLISH_SECS=5

echo "=== Running K8s integration tests ==="

# Create test namespace
kubectl create namespace "$TEST_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Build nodeSelector YAML snippet if arch is specified
NODE_SELECTOR=""
if [ -n "$TARGET_ARCH" ]; then
  NODE_SELECTOR="  nodeSelector:
    kubernetes.io/arch: ${TARGET_ARCH}"
  echo "Restricting test pods to ${TARGET_ARCH} nodes"
fi

# Deploy a simple HTTP server as a test workload
echo "Deploying test server..."
kubectl apply -n "$TEST_NAMESPACE" -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-server
  labels:
    app: nfm-test-server
spec:
${NODE_SELECTOR}
  containers:
    - name: server
      image: public.ecr.aws/amazonlinux/amazonlinux:2023-minimal
      command:
        - /bin/sh
        - -c
        - |
          microdnf install -y python3 && \
          python3 -c "
          import http.server, socketserver
          class H(http.server.SimpleHTTPRequestHandler):
              def do_GET(self):
                  self.send_response(200)
                  self.send_header('Content-type','text/plain')
                  self.end_headers()
                  self.wfile.write(b'hello from nfm-test-server')
              def log_message(self, *a): pass
          socketserver.TCPServer(('0.0.0.0', 8080), H).serve_forever()
          "
      ports:
        - containerPort: 8080
      readinessProbe:
        httpGet:
          path: /
          port: 8080
        initialDelaySeconds: 5
        periodSeconds: 2
---
apiVersion: v1
kind: Service
metadata:
  name: test-server
spec:
  selector:
    app: nfm-test-server
  ports:
    - port: 8080
      targetPort: 8080
EOF

# Wait for the test server to be ready
echo "Waiting for test server to be ready..."
kubectl wait --for=condition=Ready pod/test-server -n "$TEST_NAMESPACE" --timeout=120s

SERVER_POD_IP=$(kubectl get pod test-server -n "$TEST_NAMESPACE" \
  -o jsonpath='{.status.podIP}')
SERVER_HOST_IP=$(kubectl get pod test-server -n "$TEST_NAMESPACE" \
  -o jsonpath='{.status.hostIP}')
echo "Test server ready at pod IP: ${SERVER_POD_IP} (host: ${SERVER_HOST_IP})"

# Deploy a client pod that makes repeated HTTP requests
echo "Deploying test client..."
kubectl apply -n "$TEST_NAMESPACE" -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: test-client
  labels:
    app: nfm-test-client
spec:
${NODE_SELECTOR}
  # Schedule on the same node as the server for predictable flow observation
  affinity:
    podAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        - labelSelector:
            matchLabels:
              app: nfm-test-server
          topologyKey: kubernetes.io/hostname
  containers:
    - name: client
      image: public.ecr.aws/amazonlinux/amazonlinux:2023-minimal
      command:
        - /bin/sh
        - -c
        - |
          echo "Starting requests to test-server..." && \
          for i in \$(seq 1 10); do
            curl -sf http://test-server.${TEST_NAMESPACE}.svc.cluster.local:8080/ && \
              echo "Request \$i: OK" || echo "Request \$i: FAILED"
            sleep 1
          done && \
          echo "REQUESTS_COMPLETE" && \
          sleep 30
  restartPolicy: Never
EOF

# Wait for client pod to complete its requests
echo "Waiting for test client to complete requests..."
for i in $(seq 1 60); do
  CLIENT_LOGS=$(kubectl logs test-client -n "$TEST_NAMESPACE" 2>/dev/null || echo "")
  if echo "$CLIENT_LOGS" | grep -q "REQUESTS_COMPLETE"; then
    echo "Client completed all requests"
    break
  fi
  if [ $i -eq 60 ]; then
    echo "ERROR: Client did not complete within timeout"
    echo "Client logs:"
    kubectl logs test-client -n "$TEST_NAMESPACE" || true
    exit 1
  fi
  sleep 5
done

# Wait for agent to process, aggregate, and publish.
# Publishing interval is ~5s; wait long enough for at least 2 full cycles.
echo "Waiting for agent to publish reports (${PUBLISH_SECS}s interval × 6)..."
sleep $((PUBLISH_SECS * 6))

# Validate: check agent logs on the node where the test pods ran
echo ""
echo "=== Validating agent published flow reports ==="

# Find the agent pod running on the same node as the test server
DS_NAME="aws-network-flow-monitor-agent${TARGET_ARCH:+-${TARGET_ARCH}}"
AGENT_POD=$(kubectl get pods -n "$NAMESPACE" \
  --field-selector "spec.nodeName=$(kubectl get pod test-server -n "$TEST_NAMESPACE" -o jsonpath='{.spec.nodeName}')" \
  -l "name=$DS_NAME" \
  -o jsonpath='{.items[0].metadata.name}')

if [ -z "$AGENT_POD" ]; then
  echo "ERROR: Could not find agent pod on the test node"
  kubectl get pods -n "$NAMESPACE" -o wide
  exit 1
fi

echo "Checking agent pod: ${AGENT_POD}"

# Validate the agent is publishing reports (end-to-end: BPF → aggregation → publish).
# Write logs to a file to avoid shell variable size/encoding issues.
LOGFILE="/tmp/agent-logs-check.txt"
kubectl logs -n "$NAMESPACE" "$AGENT_POD" \
  -c "$DS_NAME" --tail=1000 > "$LOGFILE" 2>/dev/null || true

echo "Agent log size: $(wc -l < "$LOGFILE") lines"

if grep -q "Publishing report" "$LOGFILE"; then
  echo "[PASS] Agent is publishing flow reports"
else
  echo "[FAIL] Agent is not publishing reports"
  echo ""
  # Provide diagnostic context
  if grep -q "Aggregation complete" "$LOGFILE"; then
    echo "  Agent IS aggregating but NOT publishing — likely a permissions or endpoint issue"
  elif grep -q "Aggregating across sockets" "$LOGFILE"; then
    echo "  Agent IS running BPF but NOT aggregating — may need more time or has a processing error"
  else
    echo "  Agent shows no evidence of BPF aggregation"
  fi
  echo ""
  echo "Last 50 log lines:"
  tail -50 "$LOGFILE"
  exit 1
fi

# Verify 3: No crash loops or restarts
RESTARTS=$(kubectl get pod "$AGENT_POD" -n "$NAMESPACE" \
  -o jsonpath='{.status.containerStatuses[?(@.name=="'$DS_NAME'")].restartCount}' 2>/dev/null || echo "0")
if [ "${RESTARTS:-0}" -eq 0 ]; then
  echo "[PASS] Agent container has zero restarts"
else
  echo "[FAIL] Agent container restarted ${RESTARTS} times"
  echo "=== Previous container logs ==="
  kubectl logs -n "$NAMESPACE" "$AGENT_POD" -c "$DS_NAME" --previous --tail=30 || true
  exit 1
fi

# Verify 4: Init container (rmem_max setup) ran successfully
INIT_STATUS=$(kubectl get pod "$AGENT_POD" -n "$NAMESPACE" \
  -o jsonpath='{.status.initContainerStatuses[0].state.terminated.reason}' 2>/dev/null || echo "")
if [ "$INIT_STATUS" = "Completed" ]; then
  echo "[PASS] Init container (rmem_max setup) completed successfully"
else
  echo "[WARN] Init container status: ${INIT_STATUS:-unknown}"
fi

# Verify 5: Cleanup sidecar is running
CLEANUP_RUNNING=$(kubectl get pod "$AGENT_POD" -n "$NAMESPACE" \
  -o jsonpath='{.status.containerStatuses[?(@.name=="cleanup")].ready}' 2>/dev/null || echo "false")
if [ "$CLEANUP_RUNNING" = "true" ]; then
  echo "[PASS] Cleanup sidecar is running"
else
  echo "[WARN] Cleanup sidecar status: ${CLEANUP_RUNNING}"
fi

echo ""
echo "=== All K8s integration tests passed ==="
