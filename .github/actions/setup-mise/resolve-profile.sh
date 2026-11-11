#!/usr/bin/env bash
set -euo pipefail

profile=${MISE_TOOLS_PROFILE:?MISE_TOOLS_PROFILE must name a tool profile}

bpf_tools='go,bpf2go,clang,llvm-tools,clang-format'

case "$profile" in
none) tools='' ;;
go) tools='go' ;;
bpf) tools="$bpf_tools" ;;
generate) tools="$bpf_tools,gotestsum" ;;
integration) tools="$bpf_tools,kind,gotestsum" ;;
oats) tools="$bpf_tools,ginkgo" ;;
lint) tools='go,golangci-lint,hk,shellcheck,shfmt' ;;
unit) tools='go,setup-envtest,gotestsum' ;;
release) tools="$bpf_tools,java,gradle" ;;
obi-fix) tools="$bpf_tools,clang-tidy" ;;
license) tools='go,go-licenses' ;;
*)
  echo "Unknown MISE_TOOLS_PROFILE: $profile" >&2
  exit 1
  ;;
esac

printf 'MISE_ENABLE_TOOLS=%s\n' "$tools" >>"$GITHUB_ENV"
