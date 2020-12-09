#!/usr/bin/env bash
set -e

PLUGIN_NAME=$1
PLUGIN_DIR=$2
DIST_DIR=$3
BUILD_MODE=$4
VERSION=$5
CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if [ ${BUILD_MODE} == "strict" ]; then
    echo "Changing  venafiPolicyDenyAll to true"
    sed -i 's/const venafiPolicyDenyAll =.*/const venafiPolicyDenyAll = true/' plugin/pki/vcert.go
elif [ ${BUILD_MODE} == "optional" ]; then
    echo "Changing  venafiPolicyDenyAll to false"
    sed -i 's/const venafiPolicyDenyAll =.*/const venafiPolicyDenyAll = false/' plugin/pki/vcert.go
else
    echo "Can't determine build mode"
    exit 1
fi

mkdir -p ${CURRENT_DIR}/../${DIST_DIR}

for os in linux darwin windows; do
    for arch in 386 amd64; do
        if [ "${os}" == "darwin" ] && [ "${arch}" == "386" ]; then continue; fi
        case ${arch} in
            386)
                binary_name="${PLUGIN_DIR}/${os}86/${PLUGIN_NAME}"
                archive_name="${CURRENT_DIR}/../${DIST_DIR}/${PLUGIN_NAME}_${VERSION}_${os}86_${BUILD_MODE}"
                ;;
            *)
                binary_name="${PLUGIN_DIR}/${os}/${PLUGIN_NAME}"
                archive_name="${CURRENT_DIR}/../${DIST_DIR}/${PLUGIN_NAME}_${VERSION}_${os}_${BUILD_MODE}"
                ;;
        esac
        if [ ${BUILD_MODE} != "strict" ]; then
            binary_name="${binary_name}_${BUILD_MODE}"
        fi
        if [ "${os}" == "windows" ]; then
            binary_name="${binary_name}.exe"
        fi
        echo "Building plugin binary ${binary_name} for ${os}-${arch}"
        env CGO_ENABLED=0 GOOS=${os}  GOARCH=${arch} go build -ldflags '-s -w -extldflags "-static"' -a -o ${binary_name} || exit 1
        chmod +x ${binary_name}
        echo "Archiving binary into ${archive_name}.zip"
        SHA256=$(sha256sum ${binary_name}| head -c 64)
        echo "${SHA256}" > ${binary_name}.SHA256SUM
        zip -j "${archive_name}.zip" "${binary_name}" "${binary_name}.SHA256SUM"
    done
done
