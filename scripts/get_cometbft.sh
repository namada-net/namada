#!/usr/bin/env bash

set -Eo pipefail

# an example download-url
# https://github.com/tendermint/tendermint/releases/download/v0.34.13/tendermint_0.34.13_linux_amd64.tar.gz
# https://github.com/heliaxdev/tendermint/releases/download/v0.1.1-abcipp/tendermint_0.1.0-abcipp_darwin_amd64.tar.gz
CMT_MAJORMINOR="0.38"
CMT_PATCH="17"

CMT_REPO="https://github.com/cometbft/cometbft"

CMT_VERSION="${CMT_MAJORMINOR}.${CMT_PATCH}"

TARGET_PATH="/usr/local/bin"
TMP_PATH="/tmp"

error_exit()
{
    echo "Error: $1" >&2
    exit 1
}

# check for existence
CMT_EXECUTABLE=$(which cometbft)
if [ -x "$CMT_EXECUTABLE" ]; then
  CMT_EXISTS_VER=$(${CMT_EXECUTABLE} version)
fi

if [[ $CMT_EXISTS_VER == "${CMT_MAJORMINOR}" ]]; then
  echo "cometbft already exists in your current PATH with a sufficient version = $CMT_EXISTS_VER"
  echo "cometbft is located at = $(which cometbft)"
  exit
fi

read -r SYSTEM MACHINE <<< "$(uname -s -m)"

ARCH="amd64"
if [[ $MACHINE = "aarch64" ]] || [[ $MACHINE = "arm64" ]]; then
  ARCH="arm64"
fi

RELEASE_URL="${CMT_REPO}/releases/download/v${CMT_VERSION}/cometbft_${CMT_VERSION}_$(echo "${SYSTEM}" | tr '[:upper:]' '[:lower:]')_${ARCH}.tar.gz"
echo "$RELEASE_URL"

curl -LsSfo "$TMP_PATH"/cometbft.tar.gz "$RELEASE_URL" || error_exit "cometbft release download failed"

cd $TARGET_PATH
sudo tar -xvzf $TMP_PATH/cometbft.tar.gz cometbft || error_exit "cometbft release extraction failed"
