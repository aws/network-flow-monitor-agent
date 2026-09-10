#!/usr/bin/env bash

# Source shared build logic (architecture, version, cargo build)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/common.sh"

echo "***********************************************"
echo "Creating $TARGET_ARCH RPM file for Amazon Linux"
echo "***********************************************"

BUILD_ROOT="${OUT_DIR}/bin/linux"
rm -rf "${BUILD_ROOT}"

SPEC_FILE="${REPO_ROOT}/packaging/linux/network-flow-monitor-agent.spec"

rpmbuild -bb \
    --target "$TARGET_ARCH" \
    --define "AGENT_VERSION ${AGENT_VERSION}" \
    --define "_topdir ${BUILD_ROOT}/rpmbuild" \
    --define "_sourcedir ${REPO_ROOT}" \
    --buildroot "${BUILD_ROOT}" \
    "${SPEC_FILE}"

cp "${BUILD_ROOT}/rpmbuild/RPMS/${TARGET_ARCH}/"*.rpm "${OUT_DIR}/network-flow-monitor-agent.rpm"
rm -rf "${BUILD_ROOT}"

echo "***********************************************"
echo "RPM created: ${OUT_DIR}/network-flow-monitor-agent.rpm"
echo "***********************************************"
