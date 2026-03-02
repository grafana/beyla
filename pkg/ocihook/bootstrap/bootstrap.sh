#!/bin/sh
set -eu

# One-shot host bootstrap for the OCI runtime wrapper.
# This script is intended to run inside a privileged container with host root mounted at /host.
# It installs the runtime binary, writes config files, and updates docker daemon runtime config.

HOST_ROOT="${HOST_ROOT:-/host}"
ASSETS_DIR="${ASSETS_DIR:-/assets}"
PAYLOAD_DIR="${PAYLOAD_DIR:-/payload-dist}"

RUNTIME_NAME="${RUNTIME_NAME:-beyla}"
RUNTIME_HOST_PATH="${RUNTIME_HOST_PATH:-/usr/local/bin/beyla-oci-runtime}"
RUNTIME_BINARY_SOURCE="${RUNTIME_BINARY_SOURCE:-${ASSETS_DIR}/beyla-oci-runtime}"

ENV_FILE_PATH="${ENV_FILE_PATH:-/etc/beyla/oci-runtime.env}"
SYSTEMD_DROPIN_PATH="${SYSTEMD_DROPIN_PATH:-/etc/systemd/system/docker.service.d/beyla-oci-runtime.conf}"
DAEMON_JSON_PATH="${DAEMON_JSON_PATH:-/etc/docker/daemon.json}"

BOOTSTRAP_DRY_RUN="${BOOTSTRAP_DRY_RUN:-false}"
RESTART_DOCKER="${RESTART_DOCKER:-false}"

bool_true() {
  case "$(echo "$1" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

host_path() {
  # Prefix an absolute host path with HOST_ROOT for container-local access.
  p="$1"
  echo "${HOST_ROOT}${p}"
}

write_file_atomic() {
  target="$1"
  content="$2"
  tmp="${target}.tmp"
  printf "%s" "$content" > "$tmp"
  mv "$tmp" "$target"
}

ensure_dir() {
  d="$1"
  if [ ! -d "$d" ]; then
    mkdir -p "$d"
  fi
}

log() {
  printf '[bootstrap] %s\n' "$*"
}

apply_or_echo() {
  if bool_true "$BOOTSTRAP_DRY_RUN"; then
    log "dry-run: $*"
    return 0
  fi
  "$@"
}

install_runtime_binary() {
  src="$RUNTIME_BINARY_SOURCE"
  dst="$(host_path "$RUNTIME_HOST_PATH")"
  ensure_dir "$(dirname "$dst")"

  if [ ! -f "$src" ]; then
    log "error: runtime binary source not found: $src"
    exit 1
  fi

  log "installing runtime binary to ${RUNTIME_HOST_PATH}"
  if bool_true "$BOOTSTRAP_DRY_RUN"; then
    log "dry-run: install -m 0755 $src $dst"
  else
    install -m 0755 "$src" "$dst"
  fi
}

copy_instrumentation_payload() {
  sdk_version="${BEYLA_OCI_SDK_PACKAGE_VERSION:-}"
  host_payload_root="${BEYLA_OCI_HOST_INSTRUMENTATION_DIR:-}"

  if [ -z "$sdk_version" ] || [ -z "$host_payload_root" ]; then
    log "payload copy skipped: BEYLA_OCI_SDK_PACKAGE_VERSION or BEYLA_OCI_HOST_INSTRUMENTATION_DIR is not set"
    return 0
  fi

  if [ ! -d "$PAYLOAD_DIR" ]; then
    log "error: PAYLOAD_DIR does not exist (${PAYLOAD_DIR})"
    exit 1
  fi

  target="$(host_path "$host_payload_root")/${sdk_version}"

  # Validate payload layout and support legacy flat layout when present.
  has_structured_payload=false
  if [ -f "${PAYLOAD_DIR}/injector/libotelinject.so" ]; then
    has_structured_payload=true
  fi

  has_legacy_payload=false
  if [ -f "${PAYLOAD_DIR}/libotelinject.so" ]; then
    has_legacy_payload=true
  fi

  if ! $has_structured_payload && ! $has_legacy_payload; then
    log "error: payload does not contain libotelinject.so in structured or legacy layout (${PAYLOAD_DIR})"
    exit 1
  fi

  log "copying instrumentation payload into ${host_payload_root}/${sdk_version}"
  if bool_true "$BOOTSTRAP_DRY_RUN"; then
    log "dry-run: cp -a ${PAYLOAD_DIR}/. ${target}/"
    if ! $has_structured_payload && [ -f "${PAYLOAD_DIR}/libotelinject.so" ]; then
      log "dry-run: legacy payload layout detected (flat libotelinject.so), will normalize into injector/ on copy"
    fi
  else
    rm -rf "$target"
    mkdir -p "$target"
    cp -a "${PAYLOAD_DIR}/." "$target/"

    if ! $has_structured_payload && [ -f "${PAYLOAD_DIR}/libotelinject.so" ]; then
      # Normalize legacy payload layout for wrapper expectations.
      mkdir -p "${target}/injector"
      cp -f "${PAYLOAD_DIR}/libotelinject.so" "${target}/injector/libotelinject.so"
      if [ -f "${PAYLOAD_DIR}/otelinject.conf" ]; then
        cp -f "${PAYLOAD_DIR}/otelinject.conf" "${target}/injector/otelinject.conf"
      fi
    fi

    if [ ! -f "${target}/injector/libotelinject.so" ]; then
      log "error: payload copy completed but injector/libotelinject.so is still missing at ${target}"
      exit 1
    fi
  fi
}

write_env_file() {
  env_host_file="$(host_path "$ENV_FILE_PATH")"
  ensure_dir "$(dirname "$env_host_file")"

  # Keep all wrapper options explicit to make host state auditable.
  content="BEYLA_OCI_DELEGATE_RUNTIME=${BEYLA_OCI_DELEGATE_RUNTIME:-/usr/bin/runc}
BEYLA_OCI_MODE=${BEYLA_OCI_MODE:-permissive}
BEYLA_OCI_LOG_LEVEL=${BEYLA_OCI_LOG_LEVEL:-info}
BEYLA_OCI_DECISION_REPORT=${BEYLA_OCI_DECISION_REPORT:-none}
BEYLA_OCI_MUTATE_COMMANDS=${BEYLA_OCI_MUTATE_COMMANDS:-create}
BEYLA_OCI_EXISTING_LD_PRELOAD=${BEYLA_OCI_EXISTING_LD_PRELOAD:-skip}
BEYLA_OCI_SDK_PACKAGE_VERSION=${BEYLA_OCI_SDK_PACKAGE_VERSION:-v0.0.9}
BEYLA_OCI_HOST_INSTRUMENTATION_DIR=${BEYLA_OCI_HOST_INSTRUMENTATION_DIR:-/var/lib/beyla/instrumentation}
BEYLA_OCI_INTERNAL_MOUNT_DIR=${BEYLA_OCI_INTERNAL_MOUNT_DIR:-/__otel_sdk_auto_instrumentation__}
BEYLA_OCI_OPTIN_ANNOTATION=${BEYLA_OCI_OPTIN_ANNOTATION:-beyla.grafana.com/inject}
BEYLA_OCI_OPTIN_ENV_VAR=${BEYLA_OCI_OPTIN_ENV_VAR:-BEYLA_INJECT}
BEYLA_OCI_OVERRIDE_OTEL=${BEYLA_OCI_OVERRIDE_OTEL:-false}
BEYLA_OCI_DRY_RUN=${BEYLA_OCI_DRY_RUN:-false}
BEYLA_OCI_OTLP_ENDPOINT=${BEYLA_OCI_OTLP_ENDPOINT:-}
BEYLA_OCI_OTLP_PROTOCOL=${BEYLA_OCI_OTLP_PROTOCOL:-http/protobuf}
"

  log "writing wrapper env file ${ENV_FILE_PATH}"
  if bool_true "$BOOTSTRAP_DRY_RUN"; then
    log "dry-run: write ${env_host_file}"
  else
    write_file_atomic "$env_host_file" "$content"
  fi
}

write_systemd_dropin() {
  dropin_host_file="$(host_path "$SYSTEMD_DROPIN_PATH")"
  ensure_dir "$(dirname "$dropin_host_file")"

  content="[Service]
EnvironmentFile=-${ENV_FILE_PATH}
"

  log "writing systemd drop-in ${SYSTEMD_DROPIN_PATH}"
  if bool_true "$BOOTSTRAP_DRY_RUN"; then
    log "dry-run: write ${dropin_host_file}"
  else
    write_file_atomic "$dropin_host_file" "$content"
  fi
}

update_daemon_json() {
  daemon_host_file="$(host_path "$DAEMON_JSON_PATH")"
  ensure_dir "$(dirname "$daemon_host_file")"

  if [ ! -f "$daemon_host_file" ] || [ ! -s "$daemon_host_file" ]; then
    base='{}'
  else
    base="$(cat "$daemon_host_file")"
  fi

  updated="$(printf '%s' "$base" | jq \
    --arg runtime "$RUNTIME_NAME" \
    --arg path "$RUNTIME_HOST_PATH" \
    '.runtimes = (.runtimes // {}) | .runtimes[$runtime] = {"path": $path, "runtimeArgs": []}')"

  log "updating docker daemon runtime config at ${DAEMON_JSON_PATH}"
  if bool_true "$BOOTSTRAP_DRY_RUN"; then
    log "dry-run: write ${daemon_host_file}"
  else
    write_file_atomic "$daemon_host_file" "${updated}"
  fi
}

restart_docker_if_requested() {
  if ! bool_true "$RESTART_DOCKER"; then
    log "docker restart not requested; run manually: systemctl daemon-reload && systemctl restart docker"
    return 0
  fi

  if bool_true "$BOOTSTRAP_DRY_RUN"; then
    log "dry-run: chroot ${HOST_ROOT} /bin/sh -lc 'systemctl daemon-reload && systemctl restart docker'"
    return 0
  fi

  log "attempting to restart docker via host systemctl"
  if chroot "$HOST_ROOT" /bin/sh -lc 'command -v systemctl >/dev/null 2>&1'; then
    if chroot "$HOST_ROOT" /bin/sh -lc 'systemctl daemon-reload && systemctl restart docker'; then
      log "docker restarted successfully"
    else
      log "warning: unable to restart docker from bootstrap container (likely no DBus in chroot). restart manually on host."
    fi
    return 0
  fi

  log "warning: systemctl is not available in host chroot. restart docker manually."
  return 0
}

main() {
  log "starting one-shot bootstrap"
  install_runtime_binary
  copy_instrumentation_payload
  write_env_file
  write_systemd_dropin
  update_daemon_json
  restart_docker_if_requested
  log "bootstrap completed"
}

main "$@"
