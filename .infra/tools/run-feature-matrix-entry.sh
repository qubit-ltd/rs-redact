#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
matrix_file="$project_root/.infra/ci/cargo-matrix.json"
entry_name="${1:-}"

if [ -z "$entry_name" ]; then
    echo "usage: $0 MATRIX_ENTRY" >&2
    exit 2
fi
if [[ ! $entry_name =~ ^[[:alnum:]][[:alnum:]_.+-]*$ ]]; then
    echo "invalid matrix entry name: $entry_name" >&2
    exit 2
fi

cd "$project_root"

entry=$(
    jq -ce --arg name "$entry_name" '
        .checks
        | map(select(.name == $name))
        | if length == 1 then .[0] else error("matrix entry must exist exactly once") end
    ' "$matrix_file"
)
if jq -e 'has("dependency")' <<< "$entry" > /dev/null; then
    echo "dependency override entries are not supported by this project runner" >&2
    exit 2
fi
commands_json=$(jq -ce '
    .commands
    | if type == "array"
        and length > 0
        and all(.[]; type == "string" and IN("check", "build", "test", "doc", "doc-test", "clippy"))
      then .
      else error("matrix commands must be a nonempty supported string array")
      end
' <<< "$entry")

selection=()
mapfile -t packages < <(jq -r '.packages[]?' <<< "$entry")
if [ "${#packages[@]}" -eq 0 ]; then
    selection+=(--workspace)
else
    for package in "${packages[@]}"; do
        selection+=(--package "$package")
    done
fi

if [ "$(jq -r '.allFeatures // false' <<< "$entry")" = "true" ]; then
    selection+=(--all-features)
else
    if [ "$(jq -r 'if has("defaultFeatures") then .defaultFeatures else true end' <<< "$entry")" = "false" ]; then
        selection+=(--no-default-features)
    fi
    features=$(jq -r '.features // [] | join(",")' <<< "$entry")
    if [ -n "$features" ]; then
        selection+=(--features "$features")
    fi
fi

export CARGO_TARGET_DIR="$project_root/target/infra-feature-matrix/$entry_name"
mapfile -t commands < <(jq -r '.[]' <<< "$commands_json")
for command in "${commands[@]}"; do
    case "$command" in
        check | build | test)
            cargo +1.94.0 "$command" "${selection[@]}"
            ;;
        doc)
            RUSTDOCFLAGS="-D warnings" cargo +1.94.0 doc --no-deps "${selection[@]}"
            ;;
        doc-test)
            cargo +1.94.0 test --doc "${selection[@]}"
            ;;
        clippy)
            cargo +nightly-2026-06-05 clippy --all-targets "${selection[@]}" -- -D warnings
            ;;
        *)
            echo "unsupported matrix command: $command" >&2
            exit 2
            ;;
    esac
done
