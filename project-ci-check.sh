#!/bin/bash
# Project-owned bilingual documentation checks, invoked by rs-infra-ci.
set -euo pipefail

DOC_PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if ! command -v python3 > /dev/null 2>&1; then
    echo "Python 3.11 or newer is required for documentation example checks" >&2
    exit 1
fi
cargo +1.94.0 metadata --manifest-path "$DOC_PROJECT_ROOT/Cargo.toml" --locked --format-version 1 > /dev/null
if [ -f "$DOC_PROJECT_ROOT/fuzz/Cargo.toml" ]; then
    cargo +1.94.0 metadata --manifest-path "$DOC_PROJECT_ROOT/fuzz/Cargo.toml" --locked --format-version 1 > /dev/null
    cargo +nightly-2026-06-05 fmt --manifest-path "$DOC_PROJECT_ROOT/fuzz/Cargo.toml" \
        -- --check --config-path "$DOC_PROJECT_ROOT/.infra/style/rustfmt.toml"
fi
cargo +1.94.0 test --workspace --doc --verbose
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "Python 3.11 or newer is required")'
python3 -B "$DOC_PROJECT_ROOT/scripts/check_doc_examples_tests.py"
python3 -B "$DOC_PROJECT_ROOT/scripts/check_doc_examples.py"

pages_check_dir="$DOC_PROJECT_ROOT/target/infra-pages-check"
if ! command -v node > /dev/null 2>&1; then
    echo "Node.js is required for Pages compatibility checks" >&2
    exit 1
fi
node --check "$DOC_PROJECT_ROOT/.infra/pages/build-pages.mjs"
node "$DOC_PROJECT_ROOT/.infra/pages/build-pages.mjs" --self-test
node "$DOC_PROJECT_ROOT/.infra/pages/build-pages.mjs" --output "$pages_check_dir"
for page in "$pages_check_dir/index.html" "$pages_check_dir/zh_CN/index.html"; do
    test -s "$page"
    grep -Fq '<table>' "$page"
    grep -Fq '<pre><code class="language-' "$page"
    grep -Fq '<img src=' "$page"
    grep -Fq '<a href=' "$page"
    grep -Fq 'aria-current="page"' "$page"
done
grep -Fq 'href="zh_CN/"' "$pages_check_dir/index.html"
grep -Fq 'href="../index.html"' "$pages_check_dir/zh_CN/index.html"
test -s "$pages_check_dir/assets/site.css"
test -s "$pages_check_dir/coverage-badge.json"
jq -e '
    .repository == "qubit-ltd/rs-redact"
    and (.runUrl | type == "string")
    and (.commit | type == "string")
    and (.branch | type == "string")
    and (.coverage.reportUrl == "coverage/")
    and (.generatedAt | type == "string")
' "$pages_check_dir/ci-summary.json" > /dev/null
