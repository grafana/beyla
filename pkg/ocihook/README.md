# OCI Runtime Injection (Host-Level)

This package provides host-level auto-instrumentation for plain Docker/container runtime environments (without Kubernetes admission webhooks).

## What It Does

`beyla-oci-runtime` acts as an OCI runtime wrapper:

1. Docker invokes the wrapper as a custom runtime.
2. The wrapper reads the OCI bundle `config.json`.
3. If opt-in policy matches, it mutates env vars and mounts.
4. It delegates execution to the real runtime (`runc` by default).

This mirrors the Kubernetes webhook intent, but at OCI runtime level.

## Quick Start

### 1) Install on a Linux Docker Host (Bootstrap Image)

From repository root:

```bash
make oci-bootstrap-image
```

This builds:

1. `beyla-oci-payload:dev` (contains `/dist` payload from `pkg/webhook/image/Dockerfile`)
2. `beyla-oci-bootstrap:dev` (one-shot installer image)

Run bootstrap with sane defaults:

```bash
docker run --rm --privileged \
  -v /:/host \
  beyla-oci-bootstrap:dev
```

Optional explicit flags:

```bash
docker run --rm --privileged \
  -v /:/host \
  -e BEYLA_OCI_DECISION_REPORT=stderr \
  -e BEYLA_OCI_LOG_LEVEL=debug \
  -e RESTART_DOCKER=true \
  beyla-oci-bootstrap:dev
```

If you keep `RESTART_DOCKER=false` (default), restart Docker manually:

```bash
sudo systemctl daemon-reload
sudo systemctl restart docker
```

### 2) Verify Host Installation

Check runtime registration:

```bash
sudo jq -r '.runtimes.beyla.path' /etc/docker/daemon.json
```

Check wrapper env file:

```bash
sudo cat /etc/beyla/oci-runtime.env
```

Check payload layout:

```bash
sudo ls -l /var/lib/beyla/instrumentation/v0.0.9/injector/libotelinject.so
```

## Test with Docker Compose Demo

The demo file is:

`pkg/ocihook/example/docker-compose.yml`

It runs:

1. `injected-node` (opted-in via `BEYLA_INJECT=true`)
2. `baseline-node` (same runtime, no opt-in)
3. `trafficgen` (keeps HTTP traffic flowing)
4. `otel-collector` (debug exporter)

From `pkg/ocihook/example`:

```bash
docker compose up -d --force-recreate
```

Run validation script:

```bash
./validate.sh
```

Tail collector output:

```bash
docker compose logs -f otel-collector
```

Tail wrapper decision logs from container output:

```bash
docker compose logs -f injected-node baseline-node | grep -E 'ocihook.wrapper|policyMatched|mutationReason|finalStatus'
```

## Important Runtime Notes

- Opt-in selectors:
  - annotation: `beyla.grafana.com/inject=true`
  - env var: `BEYLA_INJECT=true` (default key, configurable)
- Required injected paths are container-internal paths:
  - `LD_PRELOAD=/__otel_sdk_auto_instrumentation__/injector/libotelinject.so`
  - `OTEL_INJECTOR_CONFIG_FILE=/__otel_sdk_auto_instrumentation__/injector/otelinject.conf`
- Wrapper defaults for OTEL exporters during mutation:
  - `OTEL_TRACES_EXPORTER=otlp`
  - `OTEL_METRICS_EXPORTER=otlp`
  - `OTEL_LOGS_EXPORTER=none`
- Defaults are preserved if already set and `BEYLA_OCI_OVERRIDE_OTEL=false`.
- Wrapper logs are emitted to container stderr/stdout and are normally visible via
  `docker logs` / `docker compose logs` (not necessarily via `journalctl -u docker.service`).

## Config Reference (`BEYLA_OCI_*`)

- `BEYLA_OCI_DELEGATE_RUNTIME` (`/usr/bin/runc`)
- `BEYLA_OCI_MODE` (`permissive|strict`)
- `BEYLA_OCI_LOG_LEVEL` (`debug|info|warn|error`)
- `BEYLA_OCI_DECISION_REPORT` (`none|stderr|stdout`)
- `BEYLA_OCI_MUTATE_COMMANDS` (default `create`)
- `BEYLA_OCI_EXISTING_LD_PRELOAD` (`skip|fail`)
- `BEYLA_OCI_SDK_PACKAGE_VERSION`
- `BEYLA_OCI_HOST_INSTRUMENTATION_DIR`
- `BEYLA_OCI_INTERNAL_MOUNT_DIR` (default `/__otel_sdk_auto_instrumentation__`)
- `BEYLA_OCI_OPTIN_ANNOTATION`
- `BEYLA_OCI_OPTIN_ENV_VAR`
- `BEYLA_OCI_OTLP_ENDPOINT`
- `BEYLA_OCI_OTLP_PROTOCOL`
- `BEYLA_OCI_ENABLED_SDKS` (comma-separated)
- `BEYLA_OCI_OVERRIDE_OTEL` (`true|false`)
- `BEYLA_OCI_DRY_RUN` (`true|false`)

## Additional References

- Architecture details: `ARCHITECTURE.md`
- Bootstrap image details: `bootstrap/README.md`
- Handover context: `AGENTS.md`

## Scope

Current target is Linux host-level Docker. Managed environments without host runtime control are out of scope in this phase.
