#!/bin/bash

# unset variables are errors
set -o nounset;
# any failed commands are errors
set -o errexit;

# this will bail with "unbound variable" if no arg provided
VERSION="$1";

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )";
ROOT="${DIR}/../../";

sed -i "$ROOT/flirt/Cargo.toml"      -e "s/^version = \"\([^\"]*\)\"/version = \"$VERSION\"/g";
sed -i "$ROOT/core/Cargo.toml"       -e "s/^version = \"\([^\"]*\)\"/version = \"$VERSION\"/g";
sed -i "$ROOT/pylancelot/Cargo.toml" -e "s/^version = \"\([^\"]*\)\"/version = \"$VERSION\"/g";
sed -i "$ROOT/bin/Cargo.toml"        -e "s/^version = \"\([^\"]*\)\"/version = \"$VERSION\"/g";

sed -i "$ROOT/core/Cargo.toml" \
    -e "s/\(lancelot-flirt.*\)version = \"[^\"]*\"\(.*\)$/\1version = \"$VERSION\"\2/g";
sed -i "$ROOT/bin/Cargo.toml" \
    -e "s/\(lancelot.*\)version = \"[^\"]*\"\(.*\)$/\1version = \"$VERSION\"\2/g";
sed -i "$ROOT/pylancelot/Cargo.toml" \
    -e "s/\(lancelot.*\)version = \"[^\"]*\"\(.*\)$/\1version = \"$VERSION\"\2/g";

exec git diff;
