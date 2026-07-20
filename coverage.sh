#!/bin/bash
set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BUILD_TOOLCHAIN="${RS_CI_BUILD_TOOLCHAIN:-1.94.0}"

cd "$PROJECT_ROOT"
cargo +"$BUILD_TOOLCHAIN" test --manifest-path "$PROJECT_ROOT/derive/Cargo.toml"

exec env RS_CI_PROJECT_ROOT="$PROJECT_ROOT" "$PROJECT_ROOT/.rs-ci/coverage.sh" "$@"
