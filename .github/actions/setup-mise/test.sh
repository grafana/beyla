#!/usr/bin/env bash
set -euo pipefail

action_dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

profiles=(none go bpf generate integration oats lint unit release obi-fix license)
for profile in "${profiles[@]}"; do
  output="$tmp/profile-$profile"
  : >"$output"
  MISE_TOOLS_PROFILE="$profile" GITHUB_ENV="$output" bash "$action_dir/resolve-profile.sh"
  [[ $(wc -l <"$output") -eq 1 ]]
  grep -q '^MISE_ENABLE_TOOLS=' "$output"
done

unknown_output="$tmp/profile-unknown"
: >"$unknown_output"
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
aliases = root_config.get("tool_alias", {})
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
    canonical_tools = [aliases.get(tool, tool) for tool in tools]
    assert len(canonical_tools) == len(set(canonical_tools)), (profile, canonical_tools)
    unknown = set(canonical_tools) - configured_tools
    assert not unknown, f"{profile} selects tools absent from Mise config: {sorted(unknown)}"
    resolved[profile] = canonical_tools

assert resolved["none"] == []
assert resolved["go"] == ["go"]

non_empty_profiles = set(profiles) - {"none"}
assert all("go" in resolved[profile] for profile in non_empty_profiles)

base_bpf = set(resolved["bpf"])
assert {"clang", "clang-format", "conda:llvm-tools"} <= base_bpf
assert any(tool.endswith("/cmd/bpf2go") for tool in base_bpf)
assert all(base_bpf <= set(resolved[profile]) for profile in ("generate", "integration", "oats", "release", "obi-fix"))

assert "gotestsum" in resolved["generate"]
assert {
    "go",
    "golangci-lint",
    "hk",
    "shellcheck",
    "shfmt",
    "github:cpp-linter/clang-tools-static-binaries",
    "taplo",
    "pkl",
} <= set(resolved["lint"])
assert {"setup-envtest", "gotestsum"} <= set(resolved["unit"])
assert {"java", "gradle"} <= set(resolved["release"])
assert "ginkgo" not in resolved["oats"]
assert "kind" in resolved["integration"]
PY
