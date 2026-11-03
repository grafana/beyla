#!/usr/bin/env bash
set -euo pipefail

if [[ ${MISE_ENABLE_TOOLS+x} ]]; then
  selector="set:${MISE_ENABLE_TOOLS}"
else
  selector='unset'
fi

if command -v sha256sum >/dev/null 2>&1; then
  hash=$(printf '%s' "$selector" | sha256sum | cut -d ' ' -f 1)
else
  hash=$(printf '%s' "$selector" | shasum -a 256 | cut -d ' ' -f 1)
fi

echo "hash=$hash" >> "$GITHUB_OUTPUT"
