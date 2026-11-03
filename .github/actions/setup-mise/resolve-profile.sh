#!/usr/bin/env bash
set -euo pipefail

profile=${MISE_TOOLS_PROFILE:?MISE_TOOLS_PROFILE must name a tool profile}

case "$profile" in
  none) tools='' ;;
  go) tools='go' ;;
  bpf) tools='go,bpf2go,clang,llvm-tools,clang-format' ;;
  generate) tools='go,bpf2go,clang,llvm-tools,clang-format,gotestsum' ;;
  integration) tools='go,bpf2go,clang,llvm-tools,clang-format,kind,gotestsum' ;;
  oats) tools='go,bpf2go,clang,llvm-tools,clang-format,ginkgo' ;;
  lint) tools='go,golangci-lint,dashboard-linter,clang-format,clang-tidy' ;;
  unit) tools='go,setup-envtest,gotestsum' ;;
  release) tools='go,bpf2go,clang,llvm-tools,clang-format,java,gradle' ;;
  obi-fix) tools='go,bpf2go,clang,llvm-tools,clang-format,clang-tidy' ;;
  license) tools='go,go-licenses' ;;
  *) echo "Unknown MISE_TOOLS_PROFILE: $profile" >&2; exit 1 ;;
esac

printf 'MISE_ENABLE_TOOLS=%s\n' "$tools" >> "$GITHUB_ENV"
