#!/bin/bash
# Launches an EC2 instance and outputs the instance ID.
#
# Usage: launch-instance.sh [options]
#
# Required options:
#   --ami-id <id>            AMI ID to launch
#   --instance-type <type>   Instance type (e.g. t3.medium)
#   --region <region>        AWS region
#   --instance-role <name>   IAM instance profile name
#
# Optional:
#   --name <tag>             Name tag for the instance
#   --user-data <script>     UserData script content
#   --block-device <json>    Block device mapping JSON
#   --tags <json>            Additional tags JSON (merged with Name)
#   --retry                  Enable retry with exponential backoff (for throttling)
#
# Output: Prints instance ID to stdout.
# Also exports to GITHUB_OUTPUT and GITHUB_ENV if available.

set -o errexit
set -o pipefail
set -o nounset

# Parse arguments
AMI_ID=""
INSTANCE_TYPE=""
REGION=""
INSTANCE_ROLE=""
NAME_TAG=""
USER_DATA=""
BLOCK_DEVICE=""
EXTRA_TAGS=""
RETRY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ami-id) AMI_ID="$2"; shift 2 ;;
    --instance-type) INSTANCE_TYPE="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --instance-role) INSTANCE_ROLE="$2"; shift 2 ;;
    --name) NAME_TAG="$2"; shift 2 ;;
    --user-data) USER_DATA="$2"; shift 2 ;;
    --block-device) BLOCK_DEVICE="$2"; shift 2 ;;
    --tags) EXTRA_TAGS="$2"; shift 2 ;;
    --retry) RETRY=true; shift ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# Validate required arguments
: "${AMI_ID:?--ami-id is required}"
: "${INSTANCE_TYPE:?--instance-type is required}"
: "${REGION:?--region is required}"
: "${INSTANCE_ROLE:?--instance-role is required}"

# Build tag specifications
if [ -n "$EXTRA_TAGS" ]; then
  TAG_SPEC="ResourceType=instance,Tags=${EXTRA_TAGS}"
elif [ -n "$NAME_TAG" ]; then
  TAG_SPEC="ResourceType=instance,Tags=[{Key=Name,Value=${NAME_TAG}}]"
else
  TAG_SPEC=""
fi

# Build command
CMD=(aws ec2 run-instances
  --image-id "$AMI_ID"
  --count 1
  --instance-type "$INSTANCE_TYPE"
  --iam-instance-profile "Name=${INSTANCE_ROLE}"
  --query 'Instances[0].InstanceId'
  --output text
  --region "$REGION"
)

[ -n "$TAG_SPEC" ] && CMD+=(--tag-specifications "$TAG_SPEC")
[ -n "$USER_DATA" ] && CMD+=(--user-data "$USER_DATA")
[ -n "$BLOCK_DEVICE" ] && CMD+=(--block-device-mappings "$BLOCK_DEVICE")

# Execute with optional retry
INSTANCE_ID=""
if [ "$RETRY" = true ]; then
  BACKOFF=10
  for attempt in $(seq 1 5); do
    INSTANCE_ID=$("${CMD[@]}" 2>/tmp/ec2-launch-error.txt) && break
    echo "RunInstances attempt $attempt failed, retrying in ${BACKOFF}s..." >&2
    sleep $BACKOFF
    BACKOFF=$((BACKOFF * 2))
    INSTANCE_ID=""
  done
  if [ -z "$INSTANCE_ID" ]; then
    echo "::error::Failed to launch instance after 5 retries" >&2
    cat /tmp/ec2-launch-error.txt >&2
    exit 1
  fi
else
  INSTANCE_ID=$("${CMD[@]}")
fi

# Export to GitHub Actions environment if available
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "instance-id=${INSTANCE_ID}" >> "$GITHUB_OUTPUT"
fi
if [ -n "${GITHUB_ENV:-}" ]; then
  echo "SSM_INSTANCE_ID=${INSTANCE_ID}" >> "$GITHUB_ENV"
  echo "SSM_REGION=${REGION}" >> "$GITHUB_ENV"
fi

echo "$INSTANCE_ID"
