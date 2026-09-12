#!/bin/bash
set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Rust 1.94 can emit conflicting unused inline coverage mappings across test
# binaries. Match the coverage wrapper workaround so llvm-cov retains bodies.
if [[ ${CARGO_ENCODED_RUSTFLAGS+x} ]]; then
    export CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS:+${CARGO_ENCODED_RUSTFLAGS}$'\x1f'}-Clink-dead-code"
else
    export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Clink-dead-code"
fi
exec env \
    MIN_REGION_COVERAGE="${MIN_REGION_COVERAGE:-90}" \
    RS_CI_PROJECT_ROOT="$PROJECT_ROOT" \
    "$PROJECT_ROOT/.rs-ci/ci-check.sh" "$@"
