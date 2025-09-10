#!/usr/bin/env bash

# Make a release archive from built Namada binaries and dylib(s)
# depends on cargo-about 0.5.2

set -e

VERSION="$(git describe --dirty --broken || echo 'dryrun')" # running this in gh on a -rc branch will fail without the fallback
PLATFORM="$(uname -s)-$(uname -m)"
PACKAGE_NAME="namada-${VERSION}-${PLATFORM}"
BIN="namada namadac namadan namadaw"

mkdir -p ${PACKAGE_NAME} && mkdir -p ${PACKAGE_NAME}/wasm && \
cd target/release && \
ln ${BIN} ../../${PACKAGE_NAME} && \
cd ../.. && \
ln wasm/*.*.wasm wasm/checksums.json ${PACKAGE_NAME}/wasm && \
ln LICENSE ${PACKAGE_NAME} && \
cargo about generate about.hbs --fail --output-file ${PACKAGE_NAME}/LICENSE.thirdparty && \
tar -c -z -f ${PACKAGE_NAME}.tar.gz ${PACKAGE_NAME} && \
rm -rf ${PACKAGE_NAME}
