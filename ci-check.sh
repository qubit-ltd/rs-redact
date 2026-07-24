#!/bin/bash
set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BUILD_TOOLCHAIN="${RS_CI_BUILD_TOOLCHAIN:-1.94.0}"
# Lookup branches run only in isolated Cargo fixtures with separate profiles.
PROJECT_COVERAGE_EXCLUDE_REGEX='derive/src/internal/crate_path[.]rs$'

if [ -n "${COVERAGE_EXTRA_EXCLUDE_REGEX:-}" ]; then
    PROJECT_COVERAGE_EXCLUDE_REGEX="${PROJECT_COVERAGE_EXCLUDE_REGEX}|${COVERAGE_EXTRA_EXCLUDE_REGEX}"
fi

cd "$PROJECT_ROOT"
cargo +"$BUILD_TOOLCHAIN" test --workspace --all-features
RUSTDOCFLAGS="-D warnings -D missing-docs" \
    cargo +"$BUILD_TOOLCHAIN" doc --workspace --all-features --no-deps

exec env \
    RS_CI_PROJECT_ROOT="$PROJECT_ROOT" \
    COVERAGE_EXTRA_EXCLUDE_REGEX="$PROJECT_COVERAGE_EXCLUDE_REGEX" \
    "$PROJECT_ROOT/.rs-ci/ci-check.sh" "$@"
