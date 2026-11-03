#!/usr/bin/env bash
set -euo pipefail

action_dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

hash_tools() {
  : > "$tmp"
  MISE_ENABLE_TOOLS="$1" GITHUB_OUTPUT="$tmp" bash "$action_dir/hash-tool-selector.sh"
  cut -d= -f2 "$tmp"
}

empty=$(hash_tools '')
first=$(hash_tools 'go,clang,llvm-tools,bpf2go,go-licenses,dashboard-linter,clang-tidy')
same=$(hash_tools 'go,clang,llvm-tools,bpf2go,go-licenses,dashboard-linter,clang-tidy')
other=$(hash_tools 'go')
: > "$tmp"
env -u MISE_ENABLE_TOOLS GITHUB_OUTPUT="$tmp" bash "$action_dir/hash-tool-selector.sh"
unset_value=$(cut -d= -f2 "$tmp")

[[ "$empty" =~ ^[[:xdigit:]]{64}$ ]]
[[ "$first" == "$same" && "$first" != "$other" ]]
[[ "$empty" != "$unset_value" ]]

pin=$(sed -nE 's|.*jdx/mise-action@([[:xdigit:]]{40}).*|\1|p' "$action_dir/action.yml")
[[ "$pin" =~ ^[[:xdigit:]]{40}$ ]]
grep -Fq 'install: true' "$action_dir/action.yml"
grep -Fq 'steps.tools.outputs.hash' "$action_dir/action.yml"
grep -Fq 'monorepo_root = true' "$action_dir/../../../mise.toml"
