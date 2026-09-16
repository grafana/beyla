#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "${script_dir}/.." && pwd)

if command -v terraform >/dev/null 2>&1; then
  exec terraform -chdir="${project_dir}" "$@"
fi

exec docker run --rm \
  --network host \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e AWS_PROFILE="${AWS_PROFILE:-sandbox}" \
  -v "${HOME}/.aws:/tmp/.aws:ro" \
  -v "${project_dir}:/workspace" \
  -w /workspace \
  hashicorp/terraform:1.13.5 "$@"
