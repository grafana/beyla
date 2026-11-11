#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mise_bin=${MISE_BIN:-$(command -v mise || true)}
if [[ -z "$mise_bin" || ! -x "$mise_bin" ]]; then
  echo 'mise-bpf2go-cross-target requires the configured mise binary' >&2
  exit 1
fi

# Resolve the project's already-installed host tools before switching mise to
# an empty data directory. Only bpf2go is cold-installed; its Go build reuses
# the existing Go module and build caches.
go_bin=$("$mise_bin" -C "$root" which go)
clang_bin=$("$mise_bin" -C "$root" which clang)
llvm_strip_bin=$("$mise_bin" -C "$root" which llvm-strip)
go_mod_cache=$("$go_bin" env GOMODCACHE)
go_build_cache=$("$go_bin" env GOCACHE)
host_os=$("$go_bin" env GOHOSTOS)
host_arch=$("$go_bin" env GOHOSTARCH)
mise_cache=${MISE_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/mise}
readarray -t bpf2go_spec < <(
  python3 - "$root/mise.toml" <<'PY'
import sys, tomllib

config = tomllib.load(open(sys.argv[1], "rb"))
tools = config["tools"]
matches = [key for key in tools if key.endswith("/cmd/bpf2go")]
if len(matches) != 1:
    raise SystemExit(f"expected one native bpf2go tool key, found: {matches}")
backend = matches[0]
tool = tools[backend]
version = tool if isinstance(tool, str) else tool["version"]
print(backend)
print(version)
PY
)
bpf2go_tool=${bpf2go_spec[0]}
bpf2go_version=${bpf2go_spec[1]}

if [[ "$host_os" != linux || "$host_arch" != amd64 ]]; then
  echo "this regression currently targets Linux/amd64 CI hosts, found $host_os/$host_arch" >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/home/.config/mise" "$tmp/data" "$tmp/state" "$tmp/no-install-env"
: >"$tmp/home/.config/mise/config.toml"
lock_before=$(sha256sum "$root/mise.lock" | awk '{print $1}')
start_seconds=$SECONDS

cat >"$tmp/cross_target.c" <<'C'
#define SEC(name) __attribute__((section(name), used))

SEC("xdp")
int cross_target_probe(void *ctx)
{
#ifndef __TARGET_ARCH_arm64
#error bpf2go did not select the ARM64 target
#endif
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
C

mise_env=(
  "HOME=$tmp/home"
  "XDG_CONFIG_HOME=$tmp/home/.config"
  "MISE_GLOBAL_CONFIG_FILE=$tmp/home/.config/mise/config.toml"
  "MISE_DATA_DIR=$tmp/data"
  "MISE_STATE_DIR=$tmp/state"
  "MISE_CACHE_DIR=$mise_cache"
  "MISE_TRUSTED_CONFIG_PATHS=$root"
  "MISE_ENABLE_TOOLS=$bpf2go_tool"
  "MISE_LOG_LEVEL=warn"
  "GOMODCACHE=$go_mod_cache"
  "GOCACHE=$go_build_cache"
  "GOTOOLCHAIN=local"
  "PATH=$(dirname "$go_bin"):$PATH"
  "GOOS=linux"
  "GOARCH=arm64"
)

echo 'Cold-installing bpf2go with ARM64 target environment'
env -u GOBIN "${mise_env[@]}" "$mise_bin" --locked -C "$root" exec -- bpf2go --help >/dev/null

installed_bpf2go=$(env -u GOBIN "${mise_env[@]}" "$mise_bin" --locked -C "$root" which bpf2go)
case "$installed_bpf2go" in
"$tmp/data"/*) ;;
*)
  echo "bpf2go was not installed in the isolated Mise data directory: $installed_bpf2go" >&2
  exit 1
  ;;
esac
[[ -x "$installed_bpf2go" ]]

echo 'Generating an ARM64-targeted BPF fixture'
env -u GOBIN "${mise_env[@]}" GOPACKAGE=crosscheck BPF2GO_CC="$clang_bin" BPF2GO_STRIP="$llvm_strip_bin" \
  "$mise_bin" --locked -C "$root" exec -- bash -c '
    cd "$1"
    exec bpf2go -cc "$BPF2GO_CC" -strip "$BPF2GO_STRIP" -target arm64 Cross "$2"
  ' _ "$tmp" "$tmp/cross_target.c" >/dev/null

generated_go="$tmp/cross_arm64_bpfel.go"
generated_object="$tmp/cross_arm64_bpfel.o"
[[ -s "$generated_go" && -s "$generated_object" ]]
grep -q '^//go:build arm64$' "$generated_go"

# Negative control: without install_env, Go refuses to install a cross-compiled
# bpf2go into GOBIN (or would produce a binary that cannot run on the host).
cat >"$tmp/no-install-env/mise.toml" <<TOML
[settings]
lockfile = false

[tools]
"$bpf2go_tool" = "$bpf2go_version"
TOML

negative_env=(
  "HOME=$tmp/home"
  "XDG_CONFIG_HOME=$tmp/home/.config"
  "MISE_GLOBAL_CONFIG_FILE=$tmp/home/.config/mise/config.toml"
  "MISE_DATA_DIR=$tmp/negative-data"
  "MISE_STATE_DIR=$tmp/negative-state"
  "MISE_CACHE_DIR=$mise_cache"
  "MISE_TRUSTED_CONFIG_PATHS=$tmp/no-install-env"
  "MISE_ENABLE_TOOLS=$bpf2go_tool"
  "MISE_LOG_LEVEL=warn"
  "GOMODCACHE=$go_mod_cache"
  "GOCACHE=$go_build_cache"
  "GOTOOLCHAIN=local"
  "PATH=$(dirname "$go_bin"):$PATH"
  "GOOS=linux"
  "GOARCH=arm64"
)
if negative_output=$(env -u GOBIN "${negative_env[@]}" "$mise_bin" -C "$tmp/no-install-env" exec -- bpf2go --help 2>&1); then
  echo 'bpf2go unexpectedly ran when its host install_env was omitted' >&2
  exit 1
fi
if ! grep -qiE 'cannot install cross-compiled binaries when GOBIN is set|exec format error|cannot execute binary file' <<<"$negative_output"; then
  printf 'negative control failed for an unexpected reason:\n%s\n' "$negative_output" >&2
  exit 1
fi

bytes=$(du -sb "$tmp/data" | awk '{print $1}')
elapsed_seconds=$((SECONDS - start_seconds))
lock_after=$(sha256sum "$root/mise.lock" | awk '{print $1}')
[[ "$lock_before" == "$lock_after" ]]
echo "ARM64 bpf2go regression passed (isolated install: ${bytes} bytes; reused shared Mise and Go caches; ${elapsed_seconds}s)"
