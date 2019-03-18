#!/usr/bin/env bash
set -e

PLUGIN_NAME=$1
PLUGIN_DIR=$2
BUILD_MODE=$3

if [ ${BUILD_MODE}=="strict" ]; then
    echo "Changing  venafiPolicyDenyAll to true"
    sed -i 's/const venafiPolicyDenyAll =.*/const venafiPolicyDenyAll = true/' plugin/pki/vcert.go
elif [ ${BUILD_MODE}=="optional" ]; then
    echo "Changing  venafiPolicyDenyAll to false"
    sed -i 's/const venafiPolicyDenyAll =.*/const venafiPolicyDenyAll = false/' plugin/pki/vcert.go
else
    echo "Can't determine build mode"
    exit 1
fi

for os in linux darwin windows; do
    for arch in 386 amd64; do
        if echo ${arch}|grep --quiet 386; then
            binary_name="${PLUGIN_DIR}/${os}86/${PLUGIN_NAME}_${BUILD_MODE}"
        else
            binary_name="${PLUGIN_DIR}/${os}/${PLUGIN_NAME}_${BUILD_MODE}"
        fi
        if echo ${os}|grep --quiet  windows; then
            binary_name="${binary_name}.exe"
        fi
        echo "Building plugin binary ${binary_name} for ${os}-${arch}"
        env CGO_ENABLED=0 GOOS=${os}  GOARCH=${arch} go build -ldflags '-s -w -extldflags "-static"' -a -o ${binary_name} || exit 1
        chmod +x ${binary_name}
    done
done

