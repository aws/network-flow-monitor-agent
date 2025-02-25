#!/bin/bash

# This script is used for forcing a new 'Amazon CloudWatch Network Flow Monitor Agent' DaemonSet rollout
# - A new deployment is triggered and PODs replaced with new ones
# - Used to enable PODs to acquire permissions from IRSA for the first time
# 
# RECOMMENDED to call this script via available make targets

NFM_DAEMON_SET_NAME=aws-network-flow-monitor-agent
DEFAULT_NAMESPACE=amazon-network-flow-monitor

NAMESPACE=${NAMESPACE:-$DEFAULT_NAMESPACE}

kubectl rollout restart daemonset -n ${NAMESPACE} ${NFM_DAEMON_SET_NAME}
