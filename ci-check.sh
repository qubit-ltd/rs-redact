#!/bin/bash
set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=.rs-ci/toolchains.sh
source "$PROJECT_ROOT/.rs-ci/toolchains.sh"
configure_rs_ci_toolchains
# Lookup branches run only in isolated Cargo fixtures with separate profiles.
# Proc-macro expansion executes in compiler subprocesses, whose coverage is not
# collected by cargo-llvm-cov's runtime test profile.
PROJECT_COVERAGE_EXCLUDE_REGEX='derive/src/internal/crate_path[.]rs$|derive/src/redact_expansion[.]rs$'

if [ -n "${COVERAGE_EXTRA_EXCLUDE_REGEX:-}" ]; then
    PROJECT_COVERAGE_EXCLUDE_REGEX="${PROJECT_COVERAGE_EXCLUDE_REGEX}|${COVERAGE_EXTRA_EXCLUDE_REGEX}"
fi

cd "$PROJECT_ROOT"
cargo +"$RS_CI_BUILD_TOOLCHAIN" test --workspace --all-features
RUSTDOCFLAGS="-D warnings -D missing-docs" \
    cargo +"$RS_CI_BUILD_TOOLCHAIN" doc --workspace --all-features --no-deps

exec env \
    RS_CI_PROJECT_ROOT="$PROJECT_ROOT" \
    COVERAGE_EXTRA_EXCLUDE_REGEX="$PROJECT_COVERAGE_EXCLUDE_REGEX" \
    "$PROJECT_ROOT/.rs-ci/ci-check.sh" "$@"
