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
export RS_INFRA_STYLE_TOOLCHAIN="${RS_INFRA_STYLE_TOOLCHAIN:-nightly-2026-06-05}"
if [ -f "$project_root/.infra/style/rustfmt.toml" ]; then
    export RS_INFRA_STYLE_RUSTFMT_CONFIG="$project_root/.infra/style/rustfmt.toml"
elif [ -f "$project_root/rustfmt.toml" ]; then
    export RS_INFRA_STYLE_RUSTFMT_CONFIG="$project_root/rustfmt.toml"
fi
"$project_root/.infra/tools/prepare-local-path-dependencies.sh"
last_arg=""
if [ "$#" -gt 0 ]; then
    last_arg="${!#}"
fi
if [ "$last_arg" = "plan" ] || [ "$last_arg" = "check" ]; then
    exec "$project_root/.infra/tools/infra-tool.sh" rs-infra-ci --project "$project_root" "$@"
fi
exec "$project_root/.infra/tools/infra-tool.sh" rs-infra-ci --project "$project_root" "$@" check
