#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace


TARGET_ARCH=`uname -p`

if [ -z "$TARGET_ARCH" ]
 then
   echo "Architecture name must be provided"
   exit 1
fi

if [[ "$TARGET_ARCH" != "x86_64" && "$TARGET_ARCH" != "aarch64" ]]; then
    echo "Unsupported architecture: $TARGET_ARCH"
    exit 1
fi

AGENT_VERSION=$(grep '^version' nfm-controller/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
echo "Detected agent version: $AGENT_VERSION"

cargo build --release

echo "***********************************************"
echo "Creating $TARGET_ARCH rpm file for Amazon Linux"
echo "***********************************************"

OUT_DIR=$(pwd)/out
rm -rf "${OUT_DIR}/bin/linux"

echo "Creating the rpm package $TARGET_ARCH"

SPEC_FILE="packaging/linux/network-flow-monitor-agent.spec"
BUILD_ROOT="${OUT_DIR}/bin/linux"

# Ensure build root exists
mkdir -p "${BUILD_ROOT}"

rpmbuild -bb \
         --target $TARGET_ARCH \
         --define "AGENT_VERSION ${AGENT_VERSION}" \
         --define "_topdir ${OUT_DIR}/bin/linux/rpmbuild" \
         --define "_sourcedir $(pwd)" \
         --buildroot "${BUILD_ROOT}" \
         "${SPEC_FILE}"
cp ${OUT_DIR}/bin/linux/rpmbuild/RPMS/$TARGET_ARCH/*.rpm ${OUT_DIR}/network-flow-monitor-agent.rpm
rm -rf ${OUT_DIR}/bin/linux/rpmbuild/RPMS/$TARGET_ARCH/*

echo "***********************************************"
echo "Creating $TARGET_ARCH rpm file for SUSE"
echo "***********************************************"

# SUSE RPM
rpmbuild -bb \
         --target $TARGET_ARCH \
         --define "AGENT_VERSION ${AGENT_VERSION}" \
         --define "_topdir ${OUT_DIR}/bin/linux/rpmbuild" \
         --define "_sourcedir $(pwd)" \
         --define "suse_version 1" \
         --buildroot "${BUILD_ROOT}" \
         "${SPEC_FILE}"

cp ${OUT_DIR}/bin/linux/rpmbuild/RPMS/$TARGET_ARCH/*.rpm ${OUT_DIR}/network-flow-monitor-agent.suse.rpm
rm -rf ${OUT_DIR}/bin/linux/rpmbuild/RPMS/$TARGET_ARCH/*
