#!/bin/bash

# This script is used for installing/uninstalling 'Amazon CloudWatch Network Flow Monitor Agent' Kubernetes Application
#
# For installing: ./charts/amazon-network-flow-monitor-agent/agent-k8s-install.sh
# For uninstalling: UNINSTALL=true ./charts/amazon-network-flow-monitor-agent/agent-k8s-install.sh
#
# RECOMMENDED to call this script via available make targets

NAMESPACE=${NAMESPACE:-"amazon-network-flow-monitor"}
HELM_RELEASE_NAME="amazon-network-flow-monitor"
HELM_CHARTS_DIR="$(dirname "$(realpath "$0")")/../"
VALUES_FILENAME=values.yaml

# Publicly Accessible Docker Image Repository for 'Amazon CloudWatch Network Flow Monitor'
PROD_CONTAINER_REGISTRY="602401143452.dkr.ecr.us-west-2.amazonaws.com"
export CONTAINER_REGISTRY=${CONTAINER_REGISTRY:-$PROD_CONTAINER_REGISTRY}

export LATEST_KNOWN_IMAGE_TAG="v1.0.2-eksbuild.1"
export IMAGE_TAG=${IMAGE_TAG:-$LATEST_KNOWN_IMAGE_TAG}

# Will install 'Amazon CloudWatch Network Flow Monitor Agent' Manifest Files to an existing K8s Cluster
# - If you want just to see the rendered template, add '--dry-run' to the command
function install-add-on-manifests() {
  helm install --debug -n ${NAMESPACE} ${HELM_RELEASE_NAME} ${HELM_CHARTS_DIR} -f ${HELM_CHARTS_DIR}/${VALUES_FILENAME} \
  --set image.containerRegistry=${CONTAINER_REGISTRY} \
  --set image.tag=${IMAGE_TAG}
}

# Will uninstall 'Amazon CloudWatch Network Flow Monitor Agent' Manifest Files from an existing K8s Cluster
function uninstall-add-on-manifests() {
  helm uninstall -n ${NAMESPACE} ${HELM_RELEASE_NAME}
}

if [ $UNINSTALL ]; then
  uninstall-add-on-manifests
else
  install-add-on-manifests
fi
