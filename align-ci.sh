#!/bin/bash
set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
env RS_CI_PROJECT_ROOT="$PROJECT_ROOT" "$PROJECT_ROOT/.rs-ci/align-ci.sh" "$@"

cd "$PROJECT_ROOT"
CLIPPY_TOOLCHAIN="${RS_CI_CLIPPY_TOOLCHAIN:-nightly-2026-06-05}"
cargo +"$CLIPPY_TOOLCHAIN" clippy --fix --allow-dirty --allow-staged \
    --workspace --all-targets --all-features
cargo +"$CLIPPY_TOOLCHAIN" clippy --workspace --all-targets --all-features \
    -- -D warnings
