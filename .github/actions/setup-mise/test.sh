#!/usr/bin/env bash
set -euo pipefail

action_dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

assert_profile() {
  local profile=$1
  local expected=$2

  local output="$tmp/profile-output"
  : > "$output"
  MISE_TOOLS_PROFILE="$profile" GITHUB_ENV="$output" bash "$action_dir/resolve-profile.sh"
  [[ $(cat "$output") == "MISE_ENABLE_TOOLS=$expected" ]]
}

assert_profile none ''
assert_profile go 'go'
assert_profile bpf 'go,bpf2go,clang,llvm-tools,clang-format'
assert_profile generate 'go,bpf2go,clang,llvm-tools,clang-format,gotestsum'
assert_profile integration 'go,bpf2go,clang,llvm-tools,clang-format,kind,gotestsum'
assert_profile oats 'go,bpf2go,clang,llvm-tools,clang-format,ginkgo'
assert_profile lint 'go,golangci-lint,dashboard-linter,clang-format,clang-tidy'
assert_profile unit 'go,setup-envtest,gotestsum'
assert_profile release 'go,bpf2go,clang,llvm-tools,clang-format,java,gradle'
assert_profile obi-fix 'go,bpf2go,clang,llvm-tools,clang-format,clang-tidy'
assert_profile license 'go,go-licenses'

if MISE_TOOLS_PROFILE=unknown GITHUB_ENV="$tmp/profile-output" bash "$action_dir/resolve-profile.sh" >/dev/null 2>&1; then
  echo 'Unknown Mise tool profiles must fail.' >&2
  exit 1
fi

assert_cache_result() {
  local path=$1
  local limit=$2
  local expected=$3
  local output="$tmp/cache-output"
  local summary="$tmp/cache-summary"

  : > "$output"
  : > "$summary"
  DOWNLOAD_CACHE_PATH="$path" \
    DOWNLOAD_CACHE_LIMIT_BYTES="$limit" \
    GITHUB_OUTPUT="$output" \
    GITHUB_STEP_SUMMARY="$summary" \
    HOME="$tmp/home" \
    bash "$action_dir/measure-download-cache.sh"
  [[ $(cat "$output") == "safe-to-save=$expected" ]]
}

mkdir -p "$tmp/home/empty cache" "$tmp/home/cache with spaces"
assert_cache_result '~/missing cache' 1024 false
assert_cache_result '~/empty cache' 1024 false
printf 'verified archive' > "$tmp/home/cache with spaces/download"
cache_size=$(du -sb "$tmp/home/cache with spaces" | cut -f1)
assert_cache_result '~/cache with spaces' "$((cache_size + 1))" true
assert_cache_result '~/cache with spaces' "$cache_size" true
assert_cache_result '~/cache with spaces' "$((cache_size - 1))" false

pin=$(sed -nE 's|.*jdx/mise-action@([[:xdigit:]]{40}).*|\1|p' "$action_dir/action.yml")
[[ "$pin" =~ ^[[:xdigit:]]{40}$ ]]
grep -Fq 'uses: actions/cache/restore@' "$action_dir/action.yml"
grep -Fq "hashFiles('mise.lock', '.github/actions/setup-mise/action.yml', '.github/actions/setup-mise/measure-download-cache.sh', '.github/workflows/mise-download-cache.yml')" "$action_dir/action.yml"
grep -Fq -- '-union' "$action_dir/action.yml"
grep -Fq 'cache-downloads:' "$action_dir/action.yml"
grep -Fq "inputs.cache-downloads == 'true'" "$action_dir/action.yml"
grep -Fq 'measure-download-cache.sh' "$action_dir/../../workflows/mise-download-cache.yml"
grep -Fq 'DOWNLOAD_CACHE_LIMIT_BYTES: 2147483648' "$action_dir/../../workflows/mise-download-cache.yml"
grep -Fq 'download-cache-hit:' "$action_dir/action.yml"
grep -Fq 'download-cache-key:' "$action_dir/action.yml"
grep -Fq 'download-cache-path:' "$action_dir/action.yml"
if grep -Fq 'steps.tools.outputs.hash' "$action_dir/action.yml"; then
  echo 'The shared download cache key must not depend on the selected tool profile.' >&2
  exit 1
fi
grep -Fq 'install: true' "$action_dir/action.yml"
grep -Fq 'monorepo_root = true' "$action_dir/../../../mise.toml"
