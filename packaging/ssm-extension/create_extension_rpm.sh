#!/usr/bin/env bash

# Source shared build logic (architecture, version, cargo build)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "***********************************************"
echo "Creating $TARGET_ARCH standalone NFM RPM (dependency for extension)"
echo "***********************************************"

# Build the standalone RPM first — the extension bundles it as an artifact
"${REPO_ROOT}/packaging/linux/create_rpm.sh" "$TARGET_ARCH"

NFM_RPM_PATH="${OUT_DIR}/network-flow-monitor-agent.rpm"
if [ ! -f "$NFM_RPM_PATH" ]; then
    echo "Error: Standalone NFM RPM not found at ${NFM_RPM_PATH}" >&2
    exit 1
fi

echo "***********************************************"
echo "Creating $TARGET_ARCH Extension RPM for NFM Agent SSM Supervised Extension"
echo "***********************************************"

BUILD_ROOT="${OUT_DIR}/ssm-buildroot"
TOPDIR="${OUT_DIR}/ssm-rpmbuild"
STAGING_DIR="${OUT_DIR}/ssm-staging"

rm -rf "${BUILD_ROOT}" "${TOPDIR}" "${STAGING_DIR}"
mkdir -p "${BUILD_ROOT}"
mkdir -p "${TOPDIR}/RPMS/${TARGET_ARCH}"
mkdir -p "${TOPDIR}/BUILD"
mkdir -p "${TOPDIR}/SOURCES"
mkdir -p "${TOPDIR}/SPECS"
mkdir -p "${TOPDIR}/SRPMS"
mkdir -p "${STAGING_DIR}/artifacts"

# Stage the bundled NFM RPM
cp "$NFM_RPM_PATH" "${STAGING_DIR}/artifacts/network-flow-monitor-agent.rpm"

# Stage the package directory (manifest, lifecycle scripts, config)
cp -r "${SCRIPT_DIR}/package" "${STAGING_DIR}/package"

SPEC_FILE="${SCRIPT_DIR}/network-flow-monitor-agent-ssm.spec"

rpmbuild -bb \
    --target "$TARGET_ARCH" \
    --define "AGENT_VERSION ${AGENT_VERSION}" \
    --define "_topdir ${TOPDIR}" \
    --define "_sourcedir ${STAGING_DIR}" \
    --buildroot "${BUILD_ROOT}" \
    "${SPEC_FILE}"

cp "${TOPDIR}/RPMS/${TARGET_ARCH}/"*.rpm "${OUT_DIR}/aws-ssm-networkflowmonitor.rpm"

rm -rf "${BUILD_ROOT}" "${TOPDIR}" "${STAGING_DIR}"

echo "***********************************************"
echo "Extension RPM created: ${OUT_DIR}/aws-ssm-networkflowmonitor.rpm"
echo "***********************************************"
