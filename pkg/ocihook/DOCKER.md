# Docker Integration Guide (Host-Level)

This document explains how to run `beyla-oci-runtime` as a Docker custom runtime on a Linux host.

## 1. Build the Wrapper Binary

```bash
go build -o /usr/local/bin/beyla-oci-runtime ./cmd/oci-runtime
chmod +x /usr/local/bin/beyla-oci-runtime
```

## 2. Configure Docker Runtime

Edit `/etc/docker/daemon.json` and register the wrapper runtime:

```json
{
  "runtimes": {
    "beyla": {
      "path": "/usr/local/bin/beyla-oci-runtime",
      "runtimeArgs": []
    }
  }
}
```

Restart Docker:

```bash
sudo systemctl restart docker
```

## 3. Configure Wrapper Environment

The wrapper is configured via environment variables (host process environment):

- `BEYLA_OCI_DELEGATE_RUNTIME` (default: `runc`)
- `BEYLA_OCI_MODE` (`permissive` or `strict`)
- `BEYLA_OCI_LOG_LEVEL` (`debug|info|warn|error`, default: `info`)
- `BEYLA_OCI_DECISION_REPORT` (`none|stderr|stdout`, default: `none`)
- `BEYLA_OCI_MUTATE_COMMANDS` (default: `create`)
- `BEYLA_OCI_EXISTING_LD_PRELOAD` (`skip` or `fail`)
- `BEYLA_OCI_SDK_PACKAGE_VERSION` (required for mutation)
- `BEYLA_OCI_HOST_INSTRUMENTATION_DIR` (required for mutation)
- `BEYLA_OCI_INTERNAL_MOUNT_DIR` (default: `/__otel_sdk_auto_instrumentation__`)
- `BEYLA_OCI_OPTIN_ANNOTATION` (default: `beyla.grafana.com/inject`)
- `BEYLA_OCI_OPTIN_ENV_VAR` (default: `BEYLA_INJECT`)
- `BEYLA_OCI_OTLP_ENDPOINT` (optional)
- `BEYLA_OCI_OTLP_PROTOCOL` (optional)
- `BEYLA_OCI_ENABLED_SDKS` (comma-separated; default: `java,dotnet,nodejs,python`)
- `BEYLA_OCI_OVERRIDE_OTEL` (`true|false`, default: `false`)
- `BEYLA_OCI_DRY_RUN` (`true|false`, default: `false`)

## 4. Run Container with Custom Runtime

```bash
docker run --runtime=beyla ...
```

Current policy supports explicit opt-in by either:

- OCI annotation: `beyla.grafana.com/inject=true`
- Process env var in OCI spec: `BEYLA_INJECT=true` (configurable key)

The env-var selector is often easier to use on plain Docker hosts.

## 5. Notes

- In `permissive` mode, mutation errors fall back to delegate runtime execution.
- In `strict` mode, mutation/load/save failures stop container creation.
- Existing non-Beyla `LD_PRELOAD` values are skipped by default.
- `LD_PRELOAD` and `OTEL_INJECTOR_CONFIG_FILE` must point to the in-container
  mount path (default: `/__otel_sdk_auto_instrumentation__/...`), not to host
  filesystem paths under `/var/lib/...`.
- The wrapper explicitly sets exporter defaults during mutation:
  - `OTEL_TRACES_EXPORTER=otlp`
  - `OTEL_METRICS_EXPORTER=otlp`
  - `OTEL_LOGS_EXPORTER=none`
