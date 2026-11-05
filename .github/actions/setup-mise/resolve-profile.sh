#!/usr/bin/env bash
set -euo pipefail

profile=${MISE_TOOLS_PROFILE:?MISE_TOOLS_PROFILE must name a tool profile}

bpf2go_tool='go:github.com/cilium/ebpf/cmd/bpf2go'
go_licenses_tool='go:github.com/google/go-licenses/v2'
llvm_tools_tool='conda:llvm-tools'
clang_tidy_tool='github:cpp-linter/clang-tools-static-binaries'
bpf_tools="go,$bpf2go_tool,clang,$llvm_tools_tool,clang-format"

case "$profile" in
  none) tools='' ;;
  go) tools='go' ;;
  bpf) tools="$bpf_tools" ;;
  generate) tools="$bpf_tools,gotestsum" ;;
  integration) tools="$bpf_tools,kind,gotestsum" ;;
  oats) tools="$bpf_tools,ginkgo" ;;
  lint) tools="go,golangci-lint,clang-format,$clang_tidy_tool" ;;
  unit) tools='go,setup-envtest,gotestsum' ;;
  release) tools="$bpf_tools,java,gradle" ;;
  obi-fix) tools="$bpf_tools,$clang_tidy_tool" ;;
  license) tools="go,$go_licenses_tool" ;;
  *) echo "Unknown MISE_TOOLS_PROFILE: $profile" >&2; exit 1 ;;
esac

printf 'MISE_ENABLE_TOOLS=%s\n' "$tools" >> "$GITHUB_ENV"
