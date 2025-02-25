#!/bin/bash

# This script is used for configuring IRSA for 'Amazon CloudWatch Network Flow Monitor Agent' authentication with Ingestion APIs
# - IAM Role for IRSA will be created automatically by eksctl, if it doesn't exist already;
# 
# RECOMMENDED to call this script via available make targets

NFM_SERVICE_ACCOUNT=aws-network-flow-monitor-agent-service-account
NFM_AGENT_PUBLISH_MANAGED_POLICY=arn:aws:iam::aws:policy/CloudWatchNetworkFlowMonitorAgentPublishPolicy
DEFAULT_NAMESPACE=amazon-network-flow-monitor
SUGGESTED_NFM_AGENT_PUBLISH_ROLE=CloudWatchNetworkFlowMonitorAgentPublishRole

NAMESPACE=${NAMESPACE:-$DEFAULT_NAMESPACE}
NFM_AGENT_PUBLISH_ROLE=${NFM_AGENT_PUBLISH_ROLE:-$SUGGESTED_NFM_AGENT_PUBLISH_ROLE}

if [ -z $CLUSTER_NAME ]; then
    echo "CLUSTER_NAME not defined. Aborting."
    exit 1
fi

if [ -z $REGION ]; then
    echo "REGION not defined. Aborting."
    exit 1
fi

function install-irsa() {
    echo "Installing IRSA with ${NFM_AGENT_PUBLISH_ROLE} IAM Role."
    eksctl create iamserviceaccount --cluster $CLUSTER_NAME --name $NFM_SERVICE_ACCOUNT --region $REGION \
        --namespace $NAMESPACE --role-name $NFM_AGENT_PUBLISH_ROLE --attach-policy-arn $NFM_AGENT_PUBLISH_MANAGED_POLICY \
        --override-existing-serviceaccounts --approve
}

function uninstall-irsa() {
    echo "Uninstalling IRSA with ${NFM_AGENT_PUBLISH_ROLE} IAM Role."
    eksctl delete iamserviceaccount --cluster $CLUSTER_NAME --name $NFM_SERVICE_ACCOUNT --region $REGION \
        --namespace $NAMESPACE 
}


if [ $UNINSTALL ]; then
  uninstall-irsa
else
  install-irsa
fi