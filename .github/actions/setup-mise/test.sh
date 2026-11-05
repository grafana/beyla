#!/usr/bin/env bash
set -euo pipefail

action_dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

profiles=(none go bpf generate integration oats lint unit release obi-fix license)
for profile in "${profiles[@]}"; do
  output="$tmp/profile-$profile"
  : > "$output"
  MISE_TOOLS_PROFILE="$profile" GITHUB_ENV="$output" bash "$action_dir/resolve-profile.sh"
  [[ $(wc -l < "$output") -eq 1 ]]
  grep -q '^MISE_ENABLE_TOOLS=' "$output"
done

unknown_output="$tmp/profile-unknown"
: > "$unknown_output"
if MISE_TOOLS_PROFILE=unknown GITHUB_ENV="$unknown_output" bash "$action_dir/resolve-profile.sh" >/dev/null 2>&1; then
  echo 'Unknown Mise tool profiles must fail.' >&2
  exit 1
fi
[[ ! -s "$unknown_output" ]]

# Keep the resolver's public profile names here, but validate its output as a
# contract instead of mirroring the resolver's complete tool mapping.
python3 - "$tmp" "$action_dir/../../.." "${profiles[@]}" <<'PY'
import pathlib
import sys
import tomllib

output_dir = pathlib.Path(sys.argv[1])
repo_root = pathlib.Path(sys.argv[2]).resolve()
profiles = sys.argv[3:]

root_config = tomllib.loads((repo_root / "mise.toml").read_text())
configured_tools = set(root_config.get("tools", {}))
for config_root in root_config.get("monorepo", {}).get("config_roots", []):
    config = repo_root / config_root / "mise.toml"
    with config.open("rb") as file:
        configured_tools.update(tomllib.load(file).get("tools", {}))

resolved = {}
for profile in profiles:
    lines = (output_dir / f"profile-{profile}").read_text().splitlines()
    assert len(lines) == 1 and lines[0].startswith("MISE_ENABLE_TOOLS="), (profile, lines)
    value = lines[0].removeprefix("MISE_ENABLE_TOOLS=")
    tools = value.split(",") if value else []
    assert all(tool and tool == tool.strip() for tool in tools), (profile, tools)
    assert len(tools) == len(set(tools)), (profile, tools)
    unknown = set(tools) - configured_tools
    assert not unknown, f"{profile} selects tools absent from Mise config: {sorted(unknown)}"
    resolved[profile] = tools

assert resolved["none"] == []
assert resolved["go"] == ["go"]

non_empty_profiles = set(profiles) - {"none"}
assert all("go" in resolved[profile] for profile in non_empty_profiles)

base_bpf = set(resolved["bpf"])
assert {"clang", "clang-format", "conda:llvm-tools"} <= base_bpf
assert any(tool.endswith("/cmd/bpf2go") for tool in base_bpf)
assert all(base_bpf <= set(resolved[profile]) for profile in ("generate", "integration", "oats", "release", "obi-fix"))

assert "gotestsum" in resolved["generate"]
assert {"setup-envtest", "gotestsum"} <= set(resolved["unit"])
assert {"java", "gradle"} <= set(resolved["release"])
assert "ginkgo" in resolved["oats"]
assert "kind" in resolved["integration"]
PY

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
