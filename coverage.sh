#!/bin/bash
set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Lookup branches run only in isolated Cargo fixtures with separate profiles.
PROJECT_COVERAGE_EXCLUDE_REGEX='derive/src/internal/crate_path[.]rs$'

if [ -n "${COVERAGE_EXTRA_EXCLUDE_REGEX:-}" ]; then
    PROJECT_COVERAGE_EXCLUDE_REGEX="${PROJECT_COVERAGE_EXCLUDE_REGEX}|${COVERAGE_EXTRA_EXCLUDE_REGEX}"
fi

exec env \
    RS_CI_PROJECT_ROOT="$PROJECT_ROOT" \
    COVERAGE_EXTRA_EXCLUDE_REGEX="$PROJECT_COVERAGE_EXCLUDE_REGEX" \
    "$PROJECT_ROOT/.rs-ci/coverage.sh" "$@"
