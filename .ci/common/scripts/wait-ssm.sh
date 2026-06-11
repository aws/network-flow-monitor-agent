#!/bin/bash
# Waits until an EC2 instance is running and the SSM agent is online.
#
# Usage: wait-ssm.sh <instance_id> <region> [timeout_seconds]
#
# Arguments:
#   instance_id      - EC2 instance ID
#   region           - AWS region
#   timeout_seconds  - Max wait time (default: 300)
#
# Exit codes:
#   0 - Instance is running and SSM agent is registered
#   1 - Timeout waiting for SSM readiness

set -o errexit
set -o pipefail
set -o nounset

INSTANCE_ID="$1"
REGION="$2"
TIMEOUT="${3:-300}"

# Wait for instance to reach "running" state
aws ec2 wait instance-running \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION"

# Poll for SSM agent registration
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
  READY=$(aws ssm describe-instance-information \
    --filters "Key=InstanceIds,Values=${INSTANCE_ID}" \
    --query 'length(InstanceInformationList)' \
    --output text \
    --region "$REGION" 2>/dev/null || echo "0")

  if [ "$READY" = "1" ]; then
    echo "SSM ready after ${ELAPSED}s"
    exit 0
  fi

  sleep 10
  ELAPSED=$((ELAPSED + 10))
done

echo "::error::Timeout waiting for SSM readiness after ${TIMEOUT}s"
exit 1
