#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
PACKAGE_DIR="$ROOT_DIR/packaging/deb"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
root="$tmp/root"
bin="$tmp/bin"
mkdir -p "$bin" "$root/etc/default" "$root/etc/alloy" \
  "$root/usr/lib/grafana-beyla-sdk" "$root/usr/share/grafana-beyla-sdk" \
  "$root/usr/lib/systemd/system" "$root/var/lib"

cat > "$root/etc/default/alloy" <<'EOF'
## Path:
## Description: Grafana Alloy settings
## Type:        string
## Default:     ""
## ServiceRestart: alloy
#
  # Indented vendor comments are harmless too.
# Command line options for Alloy.
#
# The configuration file holding the Alloy Default Engine config.
# Only effective if ALLOY_OTEL_MODE is disabled.
CONFIG_FILE="/etc/alloy/config.alloy"

# The configuration file holding the Alloy OTel Engine config.
# Only effective if ALLOY_OTEL_MODE is enabled.
OTEL_CONFIG_FILE="/etc/alloy/config.yaml"

# User-defined arguments to pass to the default engine (`alloy run`).
# Only effective if ALLOY_OTEL_MODE is disabled.
CUSTOM_ARGS=""

# User-defined arguments to pass to the OTel engine (`alloy otel`).
# Only effective if ALLOY_OTEL_MODE is enabled.
OTEL_CUSTOM_ARGS=""

# Set to 1, true, yes, or on (case-insensitive) to run the OTel engine
# instead of the default engine.
ALLOY_OTEL_MODE=""

# Restart on system upgrade. Defaults to true.
RESTART_ON_UPGRADE=true
EOF
printf 'pristine package config\n' > "$root/etc/alloy/config.alloy"
config_hash=$(md5sum "$root/etc/alloy/config.alloy" | awk '{print $1}')
cp "$PACKAGE_DIR/alloy-config.alloy" "$root/usr/share/grafana-beyla-sdk/config.alloy"
cp "$PACKAGE_DIR/alloy-dropin.conf" "$root/usr/share/grafana-beyla-sdk/alloy-service-dropin.conf"
cp "$PACKAGE_DIR/configure.py" "$root/usr/lib/grafana-beyla-sdk/configure.py"
cp "$PACKAGE_DIR/validate-alloy.py" "$root/usr/lib/grafana-beyla-sdk/validate-alloy.py"
printf '[Service]\nExecStart=/usr/bin/demo\n' > "$root/usr/lib/systemd/system/demo.service"

cat > "$bin/dpkg-query" <<'EOF'
#!/bin/sh
printf ' /etc/alloy/config.alloy %s\n' "$ALLOY_DEFAULT_HASH"
EOF
cat > "$bin/alloy" <<'EOF'
#!/bin/sh
echo "$*" >> "$COMMAND_LOG"
test "$1" = validate
EOF
cat > "$bin/systemctl" <<'EOF'
#!/bin/sh
echo "$*" >> "$COMMAND_LOG"
if [ "$1" = is-active ]; then test -f "$ACTIVE_FILE"; exit; fi
if [ "$1" = start ]; then touch "$ACTIVE_FILE"; fi
exit 0
EOF
chmod +x "$bin"/*

common_env=(
  "BEYLA_PACKAGE_ROOT=$root"
  "BEYLA_TEST_NO_DEBCONF=1"
  "BEYLA_SDK_MODE=sdk"
  "BEYLA_FLEET_ENABLED=false"
  "BEYLA_SDK_SERVICES=demo.service"
  "BEYLA_OPEN_PORTS=18080"
  "GRAFANA_CLOUD_OTLP_ENDPOINT=https://otlp.example/otlp"
  "GRAFANA_CLOUD_OTLP_TENANT_ID=trace-tenant"
  "GRAFANA_CLOUD_OTLP_TOKEN=trace-secret"
  "GRAFANA_CLOUD_METRICS_ENDPOINT=https://metrics.example/api/v1/push"
  "GRAFANA_CLOUD_METRICS_TENANT_ID=metrics-tenant"
  "GRAFANA_CLOUD_METRICS_TOKEN=metrics-secret"
  "GRAFANA_CLOUD_PROFILES_ENDPOINT=https://profiles.example/pyroscope"
  "GRAFANA_CLOUD_PROFILES_TENANT_ID=profiles-tenant"
  "GRAFANA_CLOUD_PROFILES_TOKEN=profiles-secret"
  "ALLOY_DEFAULT_HASH=$config_hash"
  "COMMAND_LOG=$tmp/commands"
  "ACTIVE_FILE=$tmp/alloy-active"
  "PATH=$bin:$PATH"
)

env "${common_env[@]}" "$PACKAGE_DIR/postinst" configure
[[ $(stat -c '%a' "$root/etc/grafana/beyla-sdk/alloy.env") == 600 ]]
grep -q 'CONFIG_FILE=".*/etc/grafana/beyla-sdk/config.alloy"' "$root/etc/grafana/beyla-sdk/alloy.env"
grep -q 'trace-secret' "$root/etc/grafana/beyla-sdk/alloy.env"
! grep -q 'FLEET' "$root/etc/grafana/beyla-sdk/alloy.env"
! grep -q 'remotecfg' "$root/etc/grafana/beyla-sdk/config.alloy"
grep -q '127.0.0.1:14318' "$root/etc/grafana/beyla-sdk/sdk.env"
cmp -s "$PACKAGE_DIR/alloy-dropin.conf" "$root/etc/systemd/system/alloy.service.d/50-grafana-beyla-sdk.conf"
grep -q 'start alloy.service' "$tmp/commands"
! grep -q 'restart demo.service' "$tmp/commands"

# The normal debconf path must not read optional Fleet fields while disabled,
# nor inherit Fleet values supplied by the caller's environment.
root_debconf="$tmp/debconf-root"
cp -a "$root" "$root_debconf"
rm -rf "$root_debconf/etc/grafana/beyla-sdk" \
  "$root_debconf/var/lib/grafana-beyla-sdk" \
  "$root_debconf/etc/systemd/system/alloy.service.d" \
  "$root_debconf/etc/systemd/system/demo.service.d"
mkdir -p "$root_debconf/usr/share/debconf"
cat > "$root_debconf/usr/share/debconf/confmodule" <<'DEBCONF'
db_get() {
  printf '%s\n' "$1" >> "$DEBCONF_LOG"
  case "$1" in
    beyla/mode) RET=sdk ;;
    beyla/fleet-enabled) RET=false ;;
    beyla/otlp-endpoint) RET=https://otlp.example/otlp ;;
    beyla/otlp-tenant) RET=trace-tenant ;;
    beyla/otlp-token) RET=trace-secret ;;
    beyla/metrics-endpoint) RET=https://metrics.example/api/v1/push ;;
    beyla/metrics-tenant) RET=metrics-tenant ;;
    beyla/metrics-token) RET=metrics-secret ;;
    beyla/profiles-endpoint) RET=https://profiles.example/pyroscope ;;
    beyla/profiles-tenant) RET=profiles-tenant ;;
    beyla/profiles-token) RET=profiles-secret ;;
    beyla/services) RET=demo.service ;;
    beyla/open-ports) RET=18080 ;;
    *) echo "unexpected debconf key: $1" >&2; return 1 ;;
  esac
}
db_set() { :; }
DEBCONF
debconf_env=("${common_env[@]}" "BEYLA_PACKAGE_ROOT=$root_debconf" \
  "BEYLA_TEST_NO_DEBCONF=0" "DEBCONF_LOG=$tmp/debconf.log" \
  "GRAFANA_CLOUD_FLEET_URL=https://ambient.example/remotecfg" \
  "GRAFANA_CLOUD_FLEET_INSTANCE_ID=ambient-id")
env "${debconf_env[@]}" "$PACKAGE_DIR/postinst" configure
! grep -q '^beyla/fleet-url$' "$tmp/debconf.log"
! grep -q '^beyla/fleet-instance-id$' "$tmp/debconf.log"
! grep -q 'FLEET' "$root_debconf/etc/grafana/beyla-sdk/alloy.env"
! grep -q 'remotecfg' "$root_debconf/etc/grafana/beyla-sdk/config.alloy"

# An upgrade preserves edits/credentials and restarts only the companion-owned
# collector. The mode remains install-time-only.
printf '# retained customer change\n' >> "$root/etc/grafana/beyla-sdk/alloy.env"
env "${common_env[@]}" "$PACKAGE_DIR/postinst" configure 1.2.3
grep -q '# retained customer change' "$root/etc/grafana/beyla-sdk/alloy.env"
grep -q 'restart alloy.service' "$tmp/commands"

# A customized Alloy config fails before the companion writes its active
# systemd drop-in or state marker.
root_bad="$tmp/custom-alloy"
mkdir -p "$root_bad/etc/default" "$root_bad/etc/alloy" \
  "$root_bad/usr/lib/grafana-beyla-sdk" "$root_bad/usr/share/grafana-beyla-sdk" \
  "$root_bad/var/lib"
cp "$root/etc/default/alloy" "$root_bad/etc/default/alloy"
printf 'customer config\n' > "$root_bad/etc/alloy/config.alloy"
cp "$root/usr/share/grafana-beyla-sdk/config.alloy" "$root_bad/usr/share/grafana-beyla-sdk/config.alloy"
cp "$root/usr/share/grafana-beyla-sdk/alloy-service-dropin.conf" "$root_bad/usr/share/grafana-beyla-sdk/alloy-service-dropin.conf"
cp "$root/usr/lib/grafana-beyla-sdk/configure.py" "$root_bad/usr/lib/grafana-beyla-sdk/configure.py"
cp "$root/usr/lib/grafana-beyla-sdk/validate-alloy.py" "$root_bad/usr/lib/grafana-beyla-sdk/validate-alloy.py"
bad_env=("${common_env[@]}")
for i in "${!bad_env[@]}"; do
  case "${bad_env[$i]}" in
    BEYLA_PACKAGE_ROOT=*) bad_env[$i]="BEYLA_PACKAGE_ROOT=$root_bad" ;;
    ALLOY_DEFAULT_HASH=*) bad_env[$i]=ALLOY_DEFAULT_HASH=00000000000000000000000000000000 ;;
  esac
done
if env "${bad_env[@]}" "$PACKAGE_DIR/postinst" configure; then
  echo "expected custom Alloy config guard to reject installation" >&2
  exit 1
fi
test ! -e "$root_bad/etc/systemd/system/alloy.service.d/50-grafana-beyla-sdk.conf"
test ! -e "$root_bad/var/lib/grafana-beyla-sdk/mode"

# Commented stock Alloy defaults are accepted, but a non-default setting is
# still rejected before any companion-managed state is created.
root_bad_env="$tmp/custom-alloy-env"
cp -a "$root_bad" "$root_bad_env"
printf 'pristine package config\n' > "$root_bad_env/etc/alloy/config.alloy"
printf 'CUSTOM_ARGS="--storage.path=/data"\n' >> "$root_bad_env/etc/default/alloy"
env_hash=$(md5sum "$root_bad_env/etc/alloy/config.alloy" | awk '{print $1}')
bad_env=("${common_env[@]}")
for i in "${!bad_env[@]}"; do
  case "${bad_env[$i]}" in
    BEYLA_PACKAGE_ROOT=*) bad_env[$i]="BEYLA_PACKAGE_ROOT=$root_bad_env" ;;
    ALLOY_DEFAULT_HASH=*) bad_env[$i]="ALLOY_DEFAULT_HASH=$env_hash" ;;
  esac
done
if env "${bad_env[@]}" "$PACKAGE_DIR/postinst" configure >/dev/null 2>&1; then
  echo "expected custom Alloy default settings to reject installation" >&2
  exit 1
fi
test ! -e "$root_bad_env/etc/systemd/system/alloy.service.d/50-grafana-beyla-sdk.conf"
test ! -e "$root_bad_env/var/lib/grafana-beyla-sdk/mode"

# Invalid selected workload input cleans up only the exact package template,
# so an operator can correct the service name and retry without manual cleanup.
root_retry="$tmp/retry-install"
mkdir -p "$root_retry/etc/default" "$root_retry/etc/alloy" \
  "$root_retry/usr/lib/grafana-beyla-sdk" "$root_retry/usr/share/grafana-beyla-sdk" \
  "$root_retry/usr/lib/systemd/system" "$root_retry/var/lib"
cp "$root/etc/default/alloy" "$root_retry/etc/default/alloy"
printf 'pristine package config\n' > "$root_retry/etc/alloy/config.alloy"
retry_hash=$(md5sum "$root_retry/etc/alloy/config.alloy" | awk '{print $1}')
cp "$root/usr/share/grafana-beyla-sdk/config.alloy" "$root_retry/usr/share/grafana-beyla-sdk/config.alloy"
cp "$root/usr/share/grafana-beyla-sdk/alloy-service-dropin.conf" "$root_retry/usr/share/grafana-beyla-sdk/alloy-service-dropin.conf"
cp "$root/usr/lib/grafana-beyla-sdk/configure.py" "$root_retry/usr/lib/grafana-beyla-sdk/configure.py"
cp "$root/usr/lib/grafana-beyla-sdk/validate-alloy.py" "$root_retry/usr/lib/grafana-beyla-sdk/validate-alloy.py"
retry_env=("${common_env[@]}")
for i in "${!retry_env[@]}"; do
  case "${retry_env[$i]}" in
    BEYLA_PACKAGE_ROOT=*) retry_env[$i]="BEYLA_PACKAGE_ROOT=$root_retry" ;;
    BEYLA_SDK_SERVICES=*) retry_env[$i]=BEYLA_SDK_SERVICES=missing.service ;;
    ALLOY_DEFAULT_HASH=*) retry_env[$i]="ALLOY_DEFAULT_HASH=$retry_hash" ;;
  esac
done
if env "${retry_env[@]}" "$PACKAGE_DIR/postinst" configure >/dev/null 2>&1; then
  echo "expected invalid service selection to fail" >&2
  exit 1
fi
test ! -e "$root_retry/etc/grafana/beyla-sdk/config.alloy"
test ! -e "$root_retry/etc/grafana/beyla-sdk/alloy.env"
test ! -e "$root_retry/var/lib/grafana-beyla-sdk/mode"
printf '[Service]\nExecStart=/usr/bin/demo\n' > "$root_retry/usr/lib/systemd/system/demo.service"
for i in "${!retry_env[@]}"; do
  case "${retry_env[$i]}" in BEYLA_SDK_SERVICES=*) retry_env[$i]=BEYLA_SDK_SERVICES=demo.service ;; esac
done
env "${retry_env[@]}" "$PACKAGE_DIR/postinst" configure
test -f "$root_retry/etc/systemd/system/alloy.service.d/50-grafana-beyla-sdk.conf"
test "$(cat "$root_retry/var/lib/grafana-beyla-sdk/mode")" = sdk

# Removing the package removes an unmodified owned service drop-in and leaves
# customer-edited drop-ins untouched.
env "BEYLA_PACKAGE_ROOT=$root" "ACTIVE_FILE=$tmp/alloy-active" \
  "COMMAND_LOG=$tmp/commands" "PATH=$bin:$PATH" "$PACKAGE_DIR/postrm" remove
test ! -e "$root/etc/systemd/system/demo.service.d/90-grafana-beyla-sdk.conf"

root2="$tmp/foreign-root"
mkdir -p "$root2/etc/systemd/system/demo.service.d" "$root2/var/lib/grafana-beyla-sdk"
printf 'sdk\n' > "$root2/var/lib/grafana-beyla-sdk/mode"
printf 'demo.service\n' > "$root2/var/lib/grafana-beyla-sdk/services"
printf '[Service]\n# custom edit\nEnvironment=LD_PRELOAD=/custom.so\n' \
  > "$root2/etc/systemd/system/demo.service.d/90-grafana-beyla-sdk.conf"
env "BEYLA_PACKAGE_ROOT=$root2" "COMMAND_LOG=$tmp/commands" \
  "PATH=$bin:$PATH" "$PACKAGE_DIR/postrm" remove
grep -q '/custom.so' "$root2/etc/systemd/system/demo.service.d/90-grafana-beyla-sdk.conf"

echo "Maintainer-script fixture tests passed (systemd and Alloy were stubbed)."
