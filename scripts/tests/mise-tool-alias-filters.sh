#!/usr/bin/env bash
set -euo pipefail

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/mise.toml" <<'TOML'
[settings]
lockfile = false

[tools]
"go:github.com/cilium/ebpf/cmd/bpf2go" = { version = "0.22.0", install_env = { GOOS = "linux" } }
"go:github.com/google/go-licenses/v2" = { version = "2.0.1", install_env = { GOOS = "linux" } }
"conda:llvm-tools" = { version = "22.1.8" }
"github:cpp-linter/clang-tools-static-binaries" = { version = "2026.09.01-5fb8802d", matching = "clang-tidy-22_", bin = "clang-tidy" }
go = "1.26.10"

[tool_alias]
bpf2go = "go:github.com/cilium/ebpf/cmd/bpf2go"
go-licenses = "go:github.com/google/go-licenses/v2"
llvm-tools = "conda:llvm-tools"
clang-tidy = "github:cpp-linter/clang-tools-static-binaries"
TOML

cd "$tmp"
export HOME="$tmp/home" XDG_CONFIG_HOME="$tmp/config" XDG_DATA_HOME="$tmp/xdg-data"
export XDG_CACHE_HOME="$tmp/xdg-cache" XDG_STATE_HOME="$tmp/xdg-state"
export MISE_DATA_DIR="$tmp/data" MISE_CACHE_DIR="$tmp/cache" MISE_STATE_DIR="$tmp/state"
export MISE_GLOBAL_CONFIG_FILE="$tmp/global.toml" MISE_TRUSTED_CONFIG_PATHS="$tmp"
export MISE_AUTO_INSTALL=0
mkdir -p "$HOME"
: >"$MISE_GLOBAL_CONFIG_FILE"
mise trust "$tmp/mise.toml" >/dev/null

selected_tools() {
  MISE_ENABLE_TOOLS=${1-} MISE_DISABLE_TOOLS=${2-} mise ls --json |
    python3 -c 'import json, sys; print(",".join(sorted(json.load(sys.stdin))))'
}

disabled_tools() {
  env -u MISE_ENABLE_TOOLS MISE_DISABLE_TOOLS="$1" mise ls --json |
    python3 -c 'import json, sys; print(",".join(sorted(json.load(sys.stdin))))'
}

canonical='go:github.com/cilium/ebpf/cmd/bpf2go'
licenses='go:github.com/google/go-licenses/v2'
llvm='conda:llvm-tools'
github='github:cpp-linter/clang-tools-static-binaries'
aliases='bpf2go,go-licenses,llvm-tools,clang-tidy'
canonical_tools="$llvm,$github,$canonical,$licenses"
[[ $(selected_tools bpf2go) == "$canonical" ]]
[[ $(selected_tools "$canonical") == "$canonical" ]]
[[ $(selected_tools "$aliases") == "$canonical_tools" ]]
[[ $(selected_tools "$canonical_tools") == "$canonical_tools" ]]
[[ $(disabled_tools "$aliases") == go ]]
[[ $(disabled_tools "$canonical_tools") == go ]]
[[ $(selected_tools bpf2go bpf2go) == "$canonical" ]]
[[ -z $(selected_tools '') ]]
if [[ -d "$MISE_DATA_DIR/installs" ]] && find "$MISE_DATA_DIR/installs" -mindepth 1 -print -quit | grep -q .; then
  echo 'Mise filter test unexpectedly installed tools.' >&2
  exit 1
fi
