#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cluster=${ECS_CLUSTER:-beyla-nonk8s-poc-backend}

exec "${script_dir}/service-ip.sh" checkout "${cluster}"
