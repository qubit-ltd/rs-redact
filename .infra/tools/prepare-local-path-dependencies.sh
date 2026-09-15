#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
project_parent=$(dirname "$project_root")
config="$project_root/.infra/ci/local-path-dependencies.tsv"
[ -f "$config" ] || exit 0
while IFS=$'\t' read -r relative_path repository_url branch; do
    [[ -z "$relative_path" || "$relative_path" == \#* ]] && continue
    branch=${branch%$'\r'}
    sibling_name=${relative_path#../}
    [[ "$relative_path" == ../* && "$sibling_name" =~ ^[[:alnum:]_.-]+$ && "$sibling_name" != "." && "$sibling_name" != ".." ]] || {
        echo "error: invalid local dependency path '$relative_path'" >&2; exit 1;
    }
    [[ -n "$repository_url" && -n "$branch" ]] || {
        echo "error: incomplete local dependency entry '$relative_path'" >&2; exit 1;
    }
    target="$project_parent/$sibling_name"
    [ ! -L "$target" ] || {
        echo "error: local dependency target must not be a symbolic link: '$target'" >&2; exit 1;
    }
    [ -e "$target/.git" ] && continue
    [ ! -e "$target" ] || {
        echo "error: local dependency target already exists without a Git checkout: '$target'" >&2; exit 1;
    }
    git clone --depth 1 --branch "$branch" -- "$repository_url" "$target"
done < "$config"
