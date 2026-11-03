#!/usr/bin/env bash
set -euo pipefail

: "${DOWNLOAD_CACHE_PATH:?DOWNLOAD_CACHE_PATH must point to the mise downloads-cas directory}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"

DOWNLOAD_CACHE_PATH="${DOWNLOAD_CACHE_PATH/#\~/$HOME}"
limit_bytes=${DOWNLOAD_CACHE_LIMIT_BYTES:-2147483648}
if [[ ! "$limit_bytes" =~ ^[1-9][0-9]*$ ]]; then
  echo "DOWNLOAD_CACHE_LIMIT_BYTES must be a positive integer, got: $limit_bytes" >&2
  exit 2
fi

skip_save() {
  echo "$1" >> "$GITHUB_STEP_SUMMARY"
  echo 'safe-to-save=false' >> "$GITHUB_OUTPUT"
}

if [[ ! -d "$DOWNLOAD_CACHE_PATH" ]]; then
  skip_save "No mise download cache directory was created; skipping cache save."
  exit 0
fi

first_file=$(find "$DOWNLOAD_CACHE_PATH" -type f -print -quit)
if [[ -z "$first_file" ]]; then
  skip_save "Mise download cache is empty; skipping cache save."
  exit 0
fi

size_bytes=$(du -sb "$DOWNLOAD_CACHE_PATH" | cut -f1)
human_size=$(du -sh "$DOWNLOAD_CACHE_PATH" | cut -f1)
{
  echo "Mise verified-download cache: ${human_size} (${size_bytes} bytes)"
  echo "GitHub cache publication limit: ${limit_bytes} bytes"
} | tee -a "$GITHUB_STEP_SUMMARY"

if (( size_bytes > limit_bytes )); then
  echo "::warning::Mise downloads-cas exceeds the GitHub cache publication bound; refusing to save it. Review the measured size and repository cache quota before increasing the bound."
  echo 'safe-to-save=false' >> "$GITHUB_OUTPUT"
else
  echo 'safe-to-save=true' >> "$GITHUB_OUTPUT"
fi
