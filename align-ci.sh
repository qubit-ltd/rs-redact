#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
export RS_INFRA_STYLE_TOOLCHAIN="${RS_INFRA_STYLE_TOOLCHAIN:-nightly-2026-06-05}"
build_toolchain="${RS_INFRA_BUILD_TOOLCHAIN:-1.94.0}"
if [ -f "$project_root/.infra/style/rustfmt.toml" ]; then
    export RS_INFRA_STYLE_RUSTFMT_CONFIG="$project_root/.infra/style/rustfmt.toml"
elif [ -f "$project_root/rustfmt.toml" ]; then
    export RS_INFRA_STYLE_RUSTFMT_CONFIG="$project_root/rustfmt.toml"
fi
"$project_root/.infra/tools/prepare-local-path-dependencies.sh"

sync_lockfile() {
    local manifest="$1"
    if cargo "+$build_toolchain" metadata --manifest-path "$manifest" --locked --format-version 1 > /dev/null 2>&1; then
        echo "Cargo.lock is current for $manifest"
        return
    fi
    echo "==> cargo +$build_toolchain generate-lockfile --manifest-path $manifest"
    cargo "+$build_toolchain" generate-lockfile --manifest-path "$manifest"
    cargo "+$build_toolchain" metadata --manifest-path "$manifest" --locked --format-version 1 > /dev/null
}

sync_lockfile "$project_root/Cargo.toml"
if [ -f "$project_root/fuzz/Cargo.toml" ]; then
    sync_lockfile "$project_root/fuzz/Cargo.toml"
fi

"$project_root/.infra/tools/infra-tool.sh" rs-infra-style --project "$project_root" fix "$@"
if [ -f "$project_root/fuzz/Cargo.toml" ]; then
    cargo "+$RS_INFRA_STYLE_TOOLCHAIN" fmt --manifest-path "$project_root/fuzz/Cargo.toml" \
        -- --config-path "$RS_INFRA_STYLE_RUSTFMT_CONFIG"
fi

cargo "+$RS_INFRA_STYLE_TOOLCHAIN" clippy --fix --workspace --allow-dirty --allow-staged \
    --all-targets --all-features
cargo "+$RS_INFRA_STYLE_TOOLCHAIN" clippy --workspace --all-targets --all-features -- -D warnings

if [ "${RUN_COVERAGE_CFG_CLIPPY:-0}" = "1" ]; then
    RUSTFLAGS="--cfg coverage" cargo "+$RS_INFRA_STYLE_TOOLCHAIN" clippy --workspace \
        --all-targets --all-features -- -D warnings
fi
if [ "${RUN_COVERAGE_IN_ALIGN:-0}" = "1" ]; then
    "$project_root/coverage.sh"
else
    echo "Skipping coverage; set RUN_COVERAGE_IN_ALIGN=1 to enable it."
fi
