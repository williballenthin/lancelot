#!/bin/bash

set -o errexit;
set -o nounset;
set -o pipefail;

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
PROJECT_ROOT="$( cd "$THIS_DIR"/../.. >/dev/null 2>&1 && pwd )"
cd "$PROJECT_ROOT"/pyflirt;

maturin develop --release --extras dev;
pytest;