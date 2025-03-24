#!/usr/bin/env bash
set -e

FOLDER=$1

if [ -z "$FOLDER" ]
 then
   echo "Folder name must be provided"
   exit 1
fi

if [[ "$FOLDER" == *amd64 ]]; then
 TARGET=x86_64
elif [[ "$FOLDER" == *arm64 ]]; then
 TARGET=aarch64
else
 echo "Unsupported architecture"
 exit 1
fi

cargo build --release

echo "************************************************************"
echo "Creating $FOLDER rpm file for Amazon Linux $TARGET"
echo "************************************************************"

OUT_DIR=$(pwd)/out
rm -rf "${OUT_DIR}/bin/$FOLDER/linux"

echo "Creating the rpm package $FOLDER"

SPEC_FILE="packaging/linux/amazon-nfm-agent.spec"
BUILD_ROOT="${OUT_DIR}/bin/$FOLDER/linux"

# Ensure build root exists
mkdir -p "${BUILD_ROOT}"

rpmbuild -bb \
         --target $TARGET \
         --define "release 3" \
         --define "_topdir ${OUT_DIR}/bin/$FOLDER/linux/rpmbuild" \
         --define "_sourcedir $(pwd)" \
         --buildroot "${BUILD_ROOT}" \
         "${SPEC_FILE}"
cp ${OUT_DIR}/bin/$FOLDER/linux/rpmbuild/RPMS/$TARGET/*.rpm ${OUT_DIR}/bin/$FOLDER/amazon-nfm-agent.rpm
rm -rf ${OUT_DIR}/bin/$FOLDER/linux/rpmbuild/RPMS/$TARGET/*
