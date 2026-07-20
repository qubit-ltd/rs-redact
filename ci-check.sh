#!/bin/bash
set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BUILD_TOOLCHAIN="${RS_CI_BUILD_TOOLCHAIN:-1.94.0}"

cd "$PROJECT_ROOT"
cargo +"$BUILD_TOOLCHAIN" test --workspace --all-features
RUSTDOCFLAGS="-D warnings -D missing-docs" \
    cargo +"$BUILD_TOOLCHAIN" doc --workspace --all-features --no-deps

exec env RS_CI_PROJECT_ROOT="$PROJECT_ROOT" "$PROJECT_ROOT/.rs-ci/ci-check.sh" "$@"
