#!/bin/bash
# Terminates an EC2 instance. Safe to call even if instance ID is empty.
#
# Usage: terminate-instance.sh [instance_id] [region]
#
# If no arguments provided, reads from SSM_INSTANCE_ID and SSM_REGION env vars.
# Always exits 0 (best-effort cleanup).

set -o pipefail
set -o nounset

INSTANCE_ID="${1:-${SSM_INSTANCE_ID:-}}"
REGION="${2:-${SSM_REGION:-}}"

if [ -n "$INSTANCE_ID" ] && [ -n "$REGION" ]; then
  aws ec2 terminate-instances \
    --instance-ids "$INSTANCE_ID" \
    --region "$REGION" || true
  echo "Terminated instance: ${INSTANCE_ID}"
else
  echo "No instance to terminate (INSTANCE_ID or REGION not set)"
fi
