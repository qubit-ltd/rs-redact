#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
export PYTHONDONTWRITEBYTECODE=1
python3 "$project_root/scripts/project_ci_hook_tests.py"
python3 "$project_root/scripts/check_doc_examples_tests.py"
python3 "$project_root/scripts/check_doc_examples.py"
cargo test --locked --manifest-path "$project_root/fuzz/Cargo.toml" \
  --bin command_inputs --bin multipart_body
