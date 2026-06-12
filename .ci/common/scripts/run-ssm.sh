#!/bin/bash
# Sends a shell command to an EC2 instance via SSM and waits for completion.
#
# Required environment variables:
#   SSM_INSTANCE_ID  - Target EC2 instance ID
#   SSM_REGION       - AWS region
#
# Usage: run-ssm.sh <timeout_seconds> <command...>
#
# Exit codes:
#   0 - Command succeeded
#   1 - Command failed, timed out, or was cancelled

set -o errexit
set -o pipefail
set -o nounset

INSTANCE_ID="${SSM_INSTANCE_ID:?SSM_INSTANCE_ID not set}"
REGION="${SSM_REGION:?SSM_REGION not set}"
TIMEOUT="$1"; shift
COMMAND="$*"

COMMAND_ID=$(aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunShellScript" \
  --parameters "{\"commands\":[$(echo "$COMMAND" | jq -Rs .)],\"executionTimeout\":[\"${TIMEOUT}\"]}" \
  --timeout-seconds "$TIMEOUT" \
  --output text --query 'Command.CommandId' --region "$REGION")

ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
  STATUS=$(aws ssm get-command-invocation \
    --command-id "$COMMAND_ID" \
    --instance-id "$INSTANCE_ID" \
    --query 'Status' --output text --region "$REGION" 2>/dev/null || echo "Pending")

  case "$STATUS" in
    Success)
      aws ssm get-command-invocation \
        --command-id "$COMMAND_ID" \
        --instance-id "$INSTANCE_ID" \
        --query 'StandardOutputContent' --output text --region "$REGION"
      exit 0
      ;;
    Failed|Cancelled|TimedOut)
      echo "::error::SSM command failed ($STATUS)"
      aws ssm get-command-invocation \
        --command-id "$COMMAND_ID" \
        --instance-id "$INSTANCE_ID" \
        --query 'StandardOutputContent' --output text --region "$REGION" || true
      echo "=== STDERR ==="
      aws ssm get-command-invocation \
        --command-id "$COMMAND_ID" \
        --instance-id "$INSTANCE_ID" \
        --query 'StandardErrorContent' --output text --region "$REGION" || true
      exit 1
      ;;
    *)
      printf "."
      sleep 10
      ELAPSED=$((ELAPSED + 10))
      ;;
  esac
done

echo ""
echo "::error::Timeout after ${TIMEOUT}s"
exit 1
