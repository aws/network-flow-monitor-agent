#!/bin/bash
# Renders the Helm chart with the default values and with every file in
# .ci/helm/values, validates the manifests against the Kubernetes schema,
# and checks that they reflect the values.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHART="$ROOT/charts/amazon-network-flow-monitor-agent"
VALUES_DIR="$ROOT/.ci/helm/values"
KUBECONFORM="${KUBECONFORM:-kubeconform}"

helm lint "$CHART" --set image.containerRegistry=registry.example.com

render() {
  local name=$1
  shift
  echo "== $name"
  helm template nfm "$CHART" --namespace amazon-network-flow-monitor \
    --set image.containerRegistry=registry.example.com "$@" \
    | "$KUBECONFORM" -strict -summary -kubernetes-version 1.28.0
}

render defaults
for values in "$VALUES_DIR"/*.yaml; do
  render "$(basename "$values")" -f "$values"
done

python3 "$ROOT/.ci/helm/test_chart.py" --chart "$CHART" --values "$VALUES_DIR"/*.yaml
