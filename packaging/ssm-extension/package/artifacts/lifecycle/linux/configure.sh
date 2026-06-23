#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

echo "Configuring NFM Agent extension..."

# Initialize default INI values
cgroup="default"
endpoint="default"
region="default"

if [ -n "${AWS_AGENT_CONFIG_FILENAME}" ]; then
    CONFIG_FILE="${WORKING_DIR}/agent_configuration.json"

    val=$(extract_json_value "region" "$CONFIG_FILE")   && [ -n "$val" ] && region="$val"
    val=$(extract_json_value "endpoint" "$CONFIG_FILE") && [ -n "$val" ] && endpoint="$val"
    val=$(extract_json_value "cgroup" "$CONFIG_FILE")   && [ -n "$val" ] && cgroup="$val"
else
    region="${AWS_AGENT_REGION}"
fi

# Write the INI config file
NFM_CONFIG_DIR="/opt/aws/network-flow-monitor/etc"
mkdir -p "${NFM_CONFIG_DIR}"
cat > "${NFM_CONFIG_DIR}/network-flow-monitor.ini" <<EOF
[config]
cgroup=${cgroup}
endpoint=${endpoint}
region=${region}
EOF

# Handle credentials based on identity type
case "${AWS_AGENT_IDENTITY}" in
    Imds)
        ;;
    Hybrid|Ec2Hybrid|AzureHybrid)
        mkdir -p /etc/systemd/system/network-flow-monitor.service.d
        cat > /etc/systemd/system/network-flow-monitor.service.d/credentials.conf <<EOF
[Service]
Environment="AWS_SHARED_CREDENTIALS_FILE=${WORKING_DIR}/credentials"
EOF
        systemctl daemon-reload
        ;;
esac

echo "Configuration complete"
exit 0
