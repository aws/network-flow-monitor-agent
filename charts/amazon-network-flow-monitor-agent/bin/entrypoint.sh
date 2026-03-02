#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset
set -o xtrace

# Get cgroupv2 mount created by the init container
CGROUP_PATH="/cgroup-mount/cgroup-nfm-agent"

if [[ -z "$CGROUP_PATH" ]]; then
    echo "ERROR: No cgroupv2 mount found. The cgroupv2 must have been mounted from init container by now on $CGROUP_PATH."
    exit 1
fi

echo "Using cgroup path: $CGROUP_PATH"
cd /usr/local/bin

# Get local region based on locally available EC2 metadata
IMDS_TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 600"`
echo "Successfully retrieved IMDS Token"
region=`curl -s -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/placement/region`
if [[ -z $region ]]; then
    echo -e "IMDSv2 failed, not running in an ec2 instance, exiting"
    exit 1
fi

# Use custom endpoint if provided, otherwise use default
if [[ -n "${CUSTOM_INGESTION_ENDPOINT:-}" ]]; then
    endpoint="$CUSTOM_INGESTION_ENDPOINT"
else
    endpoint="https://networkflowmonitorreports.$region.api.aws/publish"
fi

# Configure OpenMetrics arguments
OPEN_METRICS_ARGS=()
if [[ "${OPEN_METRICS:-}" == "on" ]]; then
    OPEN_METRICS_ARGS+=("--open-metrics" "on")
    if [[ -n "${OPEN_METRICS_PORT:-}" ]]; then
        OPEN_METRICS_ARGS+=("--open-metrics-port" "$OPEN_METRICS_PORT")
    fi
    if [[ -n "${OPEN_METRICS_ADDRESS:-}" ]]; then
        OPEN_METRICS_ARGS+=("--open-metrics-address" "$OPEN_METRICS_ADDRESS")
    fi
fi

PUBLISHING_ARGS=()
if [[ "${DISABLE_PUBLISHING:-false}" == "true" ]]; then
    PUBLISHING_ARGS+=("-p" "off")
fi

echo -e "Starting NetworkFlowMonitorAgent with:\n\tcgroup:${CGROUP_PATH}\n\tendpoint:${endpoint}\n\topen metrics config: ${OPEN_METRICS_ARGS[*]}\n\tpublishing: ${DISABLE_PUBLISHING:-false}"
./nfm-agent --cgroup "$CGROUP_PATH" --endpoint-region "${region}" --endpoint "${endpoint}" -k on -n on "${OPEN_METRICS_ARGS[@]}" "${PUBLISHING_ARGS[@]}"
echo "Terminating NetworkFlowMonitorAgent"