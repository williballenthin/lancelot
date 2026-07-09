#!/usr/bin/env bash

# build the jslancelot npm package:
#   1. compile the Rust crate to wasm32-unknown-unknown
#   2. generate the JS/TS glue with wasm-bindgen into ./wasm/
#   3. copy the BinExport2 .proto schema into the package
#
# requires:
#   - rustup target add wasm32-unknown-unknown
#   - clang and cmake (to cross-compile the bundled Zydis C library)
#   - wasm-bindgen-cli matching the wasm-bindgen version pinned in Cargo.toml:
#     cargo install wasm-bindgen-cli --version 0.2.100 --locked

# unset variables are errors
set -o nounset;
# any failed commands are errors
set -o errexit;
set -o pipefail;

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )";
ROOT="${DIR}/..";

# the bundled Zydis C library is cross-compiled by clang via cmake,
# which needs a toolchain file so that cmake doesn't try to link
# executables during its compiler sanity checks.
# see the "WebAssembly" section in the top-level README.md.
CMAKE_TOOLCHAIN_FILE="${ROOT}/wasm32-toolchain.cmake" \
  cargo build -p jslancelot --release --target wasm32-unknown-unknown;

wasm-bindgen \
  --target web \
  --out-dir "${DIR}/wasm" \
  --out-name jslancelot \
  "${ROOT}/target/wasm32-unknown-unknown/release/jslancelot.wasm";

cp "${ROOT}/core/src/workspace/export/binexport2.proto" "${DIR}/binexport2.proto";

du -h "${DIR}/wasm/jslancelot_bg.wasm";
