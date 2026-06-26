#!/bin/bash
# Deploys the NFM agent to a Kubernetes cluster via Helm chart.
#
# Usage: deploy-agent.sh <image-uri> <kubeconfig> [values-override-file] [arch]
#
# Arguments:
#   image-uri              Full Docker image URI (registry/repo:tag)
#   kubeconfig             Path to kubeconfig file
#   values-override-file   (Optional) Path to a Helm values override file
#   arch                   (Optional) Target architecture (amd64 or arm64).
#                          If set, restricts the DaemonSet to only nodes of this arch.
#
# The agent is deployed as a DaemonSet using the project's Helm chart.
# It waits for all pods to be ready before returning.

set -o errexit
set -o pipefail
set -o nounset

IMAGE_URI="$1"
KUBECONFIG_PATH="$2"
VALUES_OVERRIDE="${3:-}"
TARGET_ARCH="${4:-}"

export KUBECONFIG="$KUBECONFIG_PATH"

CHART_DIR="$(cd "$(dirname "$0")/../../.." && pwd)/charts/amazon-network-flow-monitor-agent"
# Use arch-specific namespace and release name to avoid collisions when
# amd64 and arm64 jobs run concurrently on the same cluster.
NAMESPACE="amazon-cloudwatch-${TARGET_ARCH:-default}"
RELEASE_NAME="nfm-agent-test-${TARGET_ARCH:-default}"

echo "=== Deploying NFM agent via Helm ==="
echo "  Image:     ${IMAGE_URI}"
echo "  Chart:     ${CHART_DIR}"
echo "  Namespace: ${NAMESPACE}"

# Clean up any stale state from a previous failed run.
# Delete and recreate the namespace to ensure no orphaned resources or
# stuck Helm releases (which can't be uninstalled if in "pending" state).
kubectl delete namespace "$NAMESPACE" --ignore-not-found --wait=true 2>/dev/null || true
kubectl create namespace "$NAMESPACE"

# Build Helm install command
HELM_CMD=(helm upgrade --install "$RELEASE_NAME" "$CHART_DIR"
  --namespace "$NAMESPACE"
  --set "image.override=${IMAGE_URI}"
  --set "env.RUST_LOG=debug"
  --set "env.LOG_REPORTS=on"
  --wait
  --timeout 5m
)

# When arch is specified, restrict to matching nodes and use arch-specific
# names for cluster-scoped resources to avoid conflicts between parallel jobs.
if [ -n "$TARGET_ARCH" ]; then
  HELM_CMD+=(--set "affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key=kubernetes.io/arch")
  HELM_CMD+=(--set "affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator=In")
  HELM_CMD+=(--set "affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0]=${TARGET_ARCH}")
  HELM_CMD+=(--set "clusterRole.name=aws-network-flow-monitor-agent-role-${TARGET_ARCH}")
  HELM_CMD+=(--set "clusterRoleBinding.name=aws-network-flow-monitor-agent-role-binding-${TARGET_ARCH}")
  HELM_CMD+=(--set "serviceAccount.name=aws-network-flow-monitor-agent-sa-${TARGET_ARCH}")
  HELM_CMD+=(--set "daemonSet.name=aws-network-flow-monitor-agent-${TARGET_ARCH}")
  echo "  Arch:      ${TARGET_ARCH} (restricting to ${TARGET_ARCH} nodes only)"
fi

if [ -n "$VALUES_OVERRIDE" ] && [ -f "$VALUES_OVERRIDE" ]; then
  HELM_CMD+=(--values "$VALUES_OVERRIDE")
  echo "  Overrides: ${VALUES_OVERRIDE}"
fi

echo ""
echo "Running: ${HELM_CMD[*]}"
"${HELM_CMD[@]}"

echo ""
echo "=== Helm release deployed ==="
helm list --namespace "$NAMESPACE"

echo ""
echo "=== DaemonSet status ==="
kubectl get daemonset -n "$NAMESPACE" -o wide

echo ""
echo "=== Pod status ==="
kubectl get pods -n "$NAMESPACE" -o wide

# Verify all DaemonSet pods are running
echo ""
echo "Waiting for all DaemonSet pods to be Running..."
DS_NAME="aws-network-flow-monitor-agent${TARGET_ARCH:+-${TARGET_ARCH}}"
for i in $(seq 1 30); do
  DESIRED=$(kubectl get daemonset "$DS_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo "0")
  READY=$(kubectl get daemonset "$DS_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.status.numberReady}' 2>/dev/null || echo "0")

  if [ "$DESIRED" -gt 0 ] && [ "$READY" -eq "$DESIRED" ]; then
    echo "All pods ready (${READY}/${DESIRED})"
    break
  fi

  if [ $i -eq 30 ]; then
    echo "ERROR: DaemonSet pods did not become ready within 5 minutes"
    echo "=== Pod descriptions ==="
    kubectl describe pods -n "$NAMESPACE" || true
    echo "=== Pod logs ==="
    kubectl logs -n "$NAMESPACE" -l "name=$DS_NAME" --tail=50 || true
    exit 1
  fi
  sleep 10
done

# Verify eBPF program is loaded (check agent logs for successful start)
echo ""
echo "=== Verifying eBPF program loaded ==="
PODS=$(kubectl get pods -n "$NAMESPACE" -l "name=$DS_NAME" \
  -o jsonpath='{.items[*].metadata.name}')

for POD in $PODS; do
  echo "--- Pod: ${POD} ---"
  # Check that the agent started and loaded ebpf program successfully
  if kubectl logs -n "$NAMESPACE" "$POD" -c "$DS_NAME" --tail=30 2>/dev/null | \
     grep -q "Aggregating across sockets\|Aggregation complete\|Publishing report"; then
    echo "  eBPF program loaded successfully"
  else
    echo "  WARNING: Could not confirm BPF attachment, dumping recent logs:"
    kubectl logs -n "$NAMESPACE" "$POD" -c "$DS_NAME" --tail=30 2>/dev/null || true
  fi
done

echo ""
echo "=== Agent deployment complete ==="
