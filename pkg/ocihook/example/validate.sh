#!/usr/bin/env bash
set -euo pipefail

# Validates OCI runtime wrapper demo expectations for the local docker-compose stack.
# - Host runtime registration and env file
# - Injected container has runtime env vars and mounted injector lib
# - Baseline container does not have injected runtime env vars

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

INJECTED_CONTAINER="ocihook-demo-injected-node"
BASELINE_CONTAINER="ocihook-demo-baseline-node"

# shellcheck disable=SC2016
INJECTED_GREP='LD_PRELOAD|OTEL_INJECTOR_CONFIG_FILE|BEYLA_INJECTOR_SDK_PKG_VERSION|OTEL_EXPORTER_OTLP_ENDPOINT'

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }

check_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    red "Missing required command: $1"
    exit 1
  fi
}

run() {
  "$@"
}

assert_non_empty() {
  local value="$1"
  local message="$2"
  if [[ -z "${value}" ]]; then
    red "FAIL: ${message}"
    exit 1
  fi
}

assert_empty() {
  local value="$1"
  local message="$2"
  if [[ -n "${value}" ]]; then
    red "FAIL: ${message}"
    printf '%s\n' "Unexpected value:"
    printf '%s\n' "${value}"
    exit 1
  fi
}

section() {
  printf '\n== %s ==\n' "$*"
}

check_cmd docker
check_cmd jq

section "Compose Services"
run docker compose -f "${COMPOSE_FILE}" ps

section "Host Runtime Registration"
runtime_path="$(run sudo jq -r '.runtimes.beyla.path // empty' /etc/docker/daemon.json || true)"
assert_non_empty "${runtime_path}" "runtime 'beyla' not found in /etc/docker/daemon.json"
green "runtime path: ${runtime_path}"

section "Host Wrapper Env File"
if [[ ! -f /etc/beyla/oci-runtime.env ]]; then
  red "FAIL: /etc/beyla/oci-runtime.env not found"
  exit 1
fi
run sudo grep -E '^BEYLA_OCI_(SDK_PACKAGE_VERSION|HOST_INSTRUMENTATION_DIR|MODE|LOG_LEVEL|DECISION_REPORT)=' /etc/beyla/oci-runtime.env || true

sdk_version="$(run sudo awk -F= '/^BEYLA_OCI_SDK_PACKAGE_VERSION=/{print $2}' /etc/beyla/oci-runtime.env | tail -n1)"
host_dir="$(run sudo awk -F= '/^BEYLA_OCI_HOST_INSTRUMENTATION_DIR=/{print $2}' /etc/beyla/oci-runtime.env | tail -n1)"
assert_non_empty "${sdk_version}" "BEYLA_OCI_SDK_PACKAGE_VERSION is empty in /etc/beyla/oci-runtime.env"
assert_non_empty "${host_dir}" "BEYLA_OCI_HOST_INSTRUMENTATION_DIR is empty in /etc/beyla/oci-runtime.env"

payload_lib="${host_dir}/${sdk_version}/injector/libotelinject.so"
legacy_payload_lib="${host_dir}/${sdk_version}/libotelinject.so"
if [[ -f "${payload_lib}" ]]; then
  green "payload lib found: ${payload_lib}"
elif [[ -f "${legacy_payload_lib}" ]]; then
  red "FAIL: legacy payload layout detected at ${legacy_payload_lib}"
  yellow "Expected layout: ${host_dir}/${sdk_version}/injector/libotelinject.so"
  yellow "Remediation: rerun latest bootstrap image to normalize payload layout."
  exit 1
else
  red "FAIL: payload lib not found at ${payload_lib}"
  exit 1
fi

section "Container Runtime Selection"
injected_runtime="$(run docker inspect "${INJECTED_CONTAINER}" | jq -r '.[0].HostConfig.Runtime')"
baseline_runtime="$(run docker inspect "${BASELINE_CONTAINER}" | jq -r '.[0].HostConfig.Runtime')"
if [[ "${injected_runtime}" != "beyla" || "${baseline_runtime}" != "beyla" ]]; then
  red "FAIL: expected both containers to use runtime=beyla"
  printf 'injected runtime: %s\n' "${injected_runtime}"
  printf 'baseline runtime: %s\n' "${baseline_runtime}"
  exit 1
fi
green "both containers use runtime=beyla"

section "Injected Container Assertions"
injected_env="$(run docker exec "${INJECTED_CONTAINER}" sh -lc "tr '\0' '\n' </proc/1/environ | grep -E '${INJECTED_GREP}' || true")"
assert_non_empty "${injected_env}" "injected container does not contain expected injected env vars"
printf '%s\n' "${injected_env}"

run docker exec "${INJECTED_CONTAINER}" sh -lc 'ls -l /__otel_sdk_auto_instrumentation__/injector/libotelinject.so'
green "injected container has mounted injector library"

section "Baseline Container Assertions"
baseline_env="$(run docker exec "${BASELINE_CONTAINER}" sh -lc "tr '\0' '\n' </proc/1/environ | grep -E '${INJECTED_GREP}' || true")"
assert_empty "${baseline_env}" "baseline container unexpectedly contains injected env vars"

yellow "baseline container mount check (expected to fail):"
run docker exec "${BASELINE_CONTAINER}" sh -lc 'ls -l /__otel_sdk_auto_instrumentation__/injector/libotelinject.so || true'

green "Validation passed: OCI wrapper mutation behavior matches expectations"
