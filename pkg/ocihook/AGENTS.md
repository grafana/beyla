# AGENTS.md - OCI Hook Fast Handover

Use this file as the minimal context for a fresh agent.
Code and docs in this directory are English-only.

## Scope

- Repo: `github.com/grafana/beyla/v3`
- Workstream: host-level OCI runtime injection for plain Docker (Linux)
- Directory: `pkg/ocihook`
- Out of scope in this phase: ECS/Fargate managed runtimes

## Goal

Port Kubernetes-style auto-instrumentation to OCI runtime level so Docker containers can be instrumented without Kubernetes admission webhooks.

## Architecture (Current)

1. Docker invokes custom runtime `beyla` -> wrapper binary `beyla-oci-runtime`.
2. Wrapper loads OCI bundle `config.json`.
3. Policy checks explicit opt-in:
   - annotation key (default `beyla.grafana.com/inject`)
   - env key (default `BEYLA_INJECT=true`)
4. Mutator injects mount + env vars.
5. Wrapper delegates to real runtime (`runc` by default).

Primary files:

- `pkg/ocihook/runtime_wrapper.go`
- `pkg/ocihook/mutate.go`
- `pkg/ocihook/policy.go`
- `pkg/ocihook/env_config.go`
- `cmd/oci-runtime/main.go`

## Canonical Operator Doc

Single source of truth:

- `pkg/ocihook/README.md`

Deprecated pointers:

- `pkg/ocihook/DOCKER.md`
- `pkg/ocihook/OPERATIONS.md`
- `pkg/ocihook/E2E.md`

## Current Known-Good Behaviors

1. Wrapper parses Docker/runc argv correctly when global flags appear before command.
2. OCI spec save preserves unknown fields (prevents `Cwd property must not be empty` breakage).
3. Env config supports fallback file `/etc/beyla/oci-runtime.env`.
4. Payload layout normalization expects:
   - `${BEYLA_OCI_HOST_INSTRUMENTATION_DIR}/${BEYLA_OCI_SDK_PACKAGE_VERSION}/injector/libotelinject.so`
5. Mutator now fills required env vars even if keys exist with empty values.

## Critical Semantics

1. `LD_PRELOAD` and `OTEL_INJECTOR_CONFIG_FILE` must use container-internal mount paths:
   - `LD_PRELOAD=/__otel_sdk_auto_instrumentation__/injector/libotelinject.so`
   - `OTEL_INJECTOR_CONFIG_FILE=/__otel_sdk_auto_instrumentation__/injector/otelinject.conf`
2. Wrapper logs are usually visible in container logs (`docker logs` / `docker compose logs`), not reliably in `journalctl -u docker.service`.
3. Wrapper exporter defaults injected by mutator:
   - `OTEL_TRACES_EXPORTER=otlp`
   - `OTEL_METRICS_EXPORTER=otlp`
   - `OTEL_LOGS_EXPORTER=none`

## Fast Repro (Do This First)

1. Build/bootstrap from repo root:
   - `make oci-bootstrap-image`
   - `docker run --rm --privileged -v /:/host beyla-oci-bootstrap:dev`
   - `sudo systemctl daemon-reload && sudo systemctl restart docker`
2. Run demo:
   - `cd pkg/ocihook/example`
   - `docker compose up -d --force-recreate`
   - `./validate.sh`
3. Observe logs:
   - `docker compose logs -f otel-collector`
   - `docker compose logs -f injected-node baseline-node | grep -E 'ocihook.wrapper|policyMatched|mutationReason|finalStatus'`

## Debug Priorities If It Fails

1. Confirm runtime registration:
   - `/etc/docker/daemon.json` has runtime `beyla` path to wrapper binary.
2. Confirm wrapper config:
   - `/etc/beyla/oci-runtime.env` has expected `BEYLA_OCI_*`.
3. Confirm payload path exists:
   - `/var/lib/beyla/instrumentation/<version>/injector/libotelinject.so`
4. Compare direct run vs compose:
   - `docker run --rm --runtime=beyla -e BEYLA_INJECT=true node:20-bookworm-slim true`
   - Then compare compose `injected-node`.
5. Inspect injected process env:
   - `tr '\0' '\n' </proc/1/environ | grep -E 'LD_PRELOAD|OTEL_INJECTOR_CONFIG_FILE|BEYLA_INJECTOR_SDK_PKG_VERSION|OTEL_EXPORTER_OTLP_ENDPOINT|OTEL_TRACES_EXPORTER|OTEL_METRICS_EXPORTER|OTEL_LOGS_EXPORTER|BEYLA_INJECT'`

## Next Work (Short List)

1. Stabilize compose-vs-direct behavior parity for all hosts.
2. Confirm telemetry appearance in collector for injected service under default demo setup.
3. Optionally add decision counters/metrics for easier production diagnostics.

## Update Rule

Keep this file short. Add only:

1. Current blockers
2. Proven fixes
3. Canonical commands

Do not append long historical changelogs here.
