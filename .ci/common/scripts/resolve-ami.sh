#!/bin/bash
# Resolves the latest AMI ID matching a name filter.
#
# Usage: resolve-ami.sh <region> <ami_filter> [owner]
#
# Arguments:
#   region      - AWS region to search in
#   ami_filter  - Name filter pattern (e.g. "amzn2-ami-kernel-5.10-hvm-*-x86_64-gp2")
#   owner       - AMI owner (default: "amazon")
#
# Output: Prints the AMI ID to stdout.
# Exit codes:
#   0 - AMI found
#   1 - No AMI matching the filter

set -o errexit
set -o pipefail
set -o nounset

REGION="$1"
AMI_FILTER="$2"
OWNER="${3:-amazon}"

AMI_ID=$(aws ec2 describe-images \
  --owners "$OWNER" \
  --filters "Name=name,Values=${AMI_FILTER}" "Name=state,Values=available" \
  --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
  --output text \
  --region "$REGION")

if [ "$AMI_ID" = "None" ] || [ -z "$AMI_ID" ]; then
  echo "::error::No AMI found for filter: ${AMI_FILTER} (owner: ${OWNER})" >&2
  exit 1
fi

echo "$AMI_ID"
