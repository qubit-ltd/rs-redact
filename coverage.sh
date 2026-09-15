#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
export CARGO_INCREMENTAL=1
# Rust 1.94 can emit conflicting unused inline coverage mappings across test
# binaries. Retain those bodies so llvm-cov merges their executed counters.
if [[ ${CARGO_ENCODED_RUSTFLAGS+x} ]]; then
    export CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS:+${CARGO_ENCODED_RUSTFLAGS}$'\x1f'}-Clink-dead-code"
else
    export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Clink-dead-code"
fi
"$project_root/.infra/tools/prepare-local-path-dependencies.sh"
"$project_root/.infra/tools/infra-tool.sh" rs-infra-coverage --project "$project_root" collect "$@"
"$project_root/.infra/tools/coverage-report.sh"
