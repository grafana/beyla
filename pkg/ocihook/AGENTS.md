# AGENTS.md - OCI Hook Work Context

This file tracks architecture and implementation context for AI/human handover.
Keep it updated whenever behavior, assumptions, or roadmap changes.

## Project Context

- Repository: `github.com/grafana/beyla/v3`
- Workstream: host-level auto-instrumentation for plain Docker/container runtime
- Directory: `pkg/ocihook`
- Date initialized: 2026-03-02

## Objective

Port Kubernetes webhook-style injection behavior to a lower runtime layer so instrumentation can work without Kubernetes.

## Current Stage

- Stage: Phase 2 (hardening)
- Status: In progress (dry-run, logging, and local E2E recipe added)

## Key Decisions (So Far)

1. Primary strategy is OCI runtime wrapper (not Kubernetes admission).
2. Wrapper mutates OCI `config.json` before delegating to real runtime.
3. Focus on Docker host-level compatibility first.
4. ECS/Fargate compatibility intentionally out of scope for now.
5. Code and docs in this directory must remain in English.

## Architectural Summary

- Intercept runtime commands (`create`/`run`) in a wrapper binary.
- Load OCI bundle spec.
- Apply selection policy.
- Inject mounts and environment variables.
- Delegate to `runc` (or configured runtime).

See `ARCHITECTURE.md` for detailed flow and phased plan.

## Reuse Candidates from Existing Beyla Code

- Environment variable semantics from `pkg/webhook/mutator.go` and `pkg/webhook/env_vars.go`.
- SDK language enable/disable behavior.
- SDK version tagging concept (`BEYLA_INJECTOR_SDK_PKG_VERSION`).

## Non-Reusable Kubernetes-Specific Pieces

- AdmissionReview handling and JSON patches.
- Kubernetes metadata matching logic.
- Pod/deployment auto-restart logic.

## Confirmed Runtime Decisions

1. Selection policy defaults to explicit opt-in.
2. Existing non-Beyla `LD_PRELOAD` causes skip (not fail).
3. Mutation coverage in v1 is `create` only.
4. Existing `OTEL_*` env vars are preserved by default (no override).

## Implemented in Phase 0

1. `config.go`: base config model and defaults for policy and mutation behavior.
2. `oci_spec.go`: minimal OCI `config.json` load/save helpers plus local spec structs.
3. `policy.go`: command + annotation opt-in policy evaluator.
4. `mutate.go`: idempotent env/mount injector with language SDK disable controls.
5. `policy_test.go` and `mutate_test.go`: unit tests for decisions and mutation behavior.

## Implemented in Phase 1 (Current Iteration)

1. `runtime_wrapper.go`: wrapper orchestration with:
   - command and bundle path resolution
   - mutation gating by configured commands
   - policy evaluation + mutation + save flow
   - strict/permissive behavior handling
   - delegate execution to configured runtime binary
2. `runtime_wrapper_test.go`: tests for:
   - bundle flag parsing variants
   - non-mutating command passthrough
   - create-path mutation and save behavior
   - strict/permissive handling on spec loading errors
3. `env_config.go`: environment-based runtime wrapper configuration and validation.
4. `env_config_test.go`: unit tests for env parsing and validation.
5. `cmd/oci-runtime/main.go`: executable entrypoint using passthrough OCI args.
6. `DOCKER.md`: host-level Docker runtime registration and configuration guide.
7. `Makefile`: `compile-oci-runtime` target to build `bin/oci-runtime`.

## Implemented in Phase 2 (Current Iteration)

1. Added `DryRun` support in config and env parsing (`BEYLA_OCI_DRY_RUN`).
2. Added structured wrapper logs for invocation, policy, mutation, and fallback decisions.
3. Improved delegate error wrapping with runtime path and exit code context.
4. Added dry-run wrapper unit test to validate no spec persistence.
5. Added `E2E.md` with a local reproducible mutation workflow using a harmless delegate.
6. Extended selection policy with a plain-Docker-friendly env selector fallback:
   - annotation selector: `beyla.grafana.com/inject=true`
   - process env selector: `BEYLA_INJECT=true` (key configurable via env)
7. Added integration-style wrapper tests with real on-disk OCI bundle files:
   - mutation path persists env/mount updates
   - dry-run path does not persist `config.json` mutations
8. Added `OPERATIONS.md` for host deployment lifecycle:
   - systemd env wiring for Docker daemon
   - host path layout recommendations
   - upgrade and rollback procedures
   - operational verification checklist
9. Added configurable wrapper log verbosity via `BEYLA_OCI_LOG_LEVEL`:
   - validated values: `debug`, `info`, `warn`, `error`
   - `cmd/oci-runtime` now configures `slog` level from runtime config
10. Added machine-readable decision reports via `BEYLA_OCI_DECISION_REPORT`:
   - targets: `none`, `stderr`, `stdout`
   - report includes command, bundle, policy outcome, mutation result, save/delegate flags, final status, and error text
11. Added runnable Docker Compose demo under `pkg/ocihook/example/`:
   - `docker-compose.yml`: injected vs baseline service comparison on runtime `beyla`
   - `otel-collector-config.yml`: local OTLP receiver + logging exporter
   - `validate.sh`: one-command verification script for host/runtime/container assertions
12. Added one-shot Linux host bootstrap container under `pkg/ocihook/bootstrap/`:
   - `Dockerfile`: packages bootstrap script + prebuilt `bin/oci-runtime`
   - `bootstrap.sh`: installs runtime binary, env file, systemd drop-in, and docker runtime registration
   - `README.md`: build/run/dry-run usage and payload-copy mode
13. Bootstrap now embeds `/dist` payload from webhook image as source of truth:
   - bootstrap `Dockerfile` copies `/dist` from a payload image build
   - `make oci-bootstrap-image` builds payload + bootstrap images in one flow
14. Fixed wrapper command parsing for Docker/runc argv format:
   - supports global runtime flags before command token (e.g., `--root ... create ...`)
   - prevents false non-mutation when command was previously parsed as a flag
   - covered by dedicated unit tests
15. Added config fallback loading from `/etc/beyla/oci-runtime.env`:
   - used when `BEYLA_OCI_*` env vars are not propagated to runtime process
   - env vars still override file values when present
16. Hardened bootstrap payload copy:
   - replaces target version directory atomically by copy overwrite
   - normalizes legacy flat payload layout into expected `injector/` structure
17. Fixed critical OCI spec persistence bug:
   - preserving unknown top-level and `process.*` fields (e.g., `process.cwd`, `process.args`)
   - avoids breaking container startup with errors like `Cwd property must not be empty`
18. Made bootstrap docker restart attempt non-fatal when chroot/systemd DBus is unavailable.
19. Aligned OCI mutator OTEL exporter defaults with webhook-style explicit behavior:
   - sets `OTEL_TRACES_EXPORTER=otlp`
   - sets `OTEL_METRICS_EXPORTER=otlp`
   - sets `OTEL_LOGS_EXPORTER=none`
   - respects existing values when `BEYLA_OCI_OVERRIDE_OTEL=false`
20. Added info-level wrapper decision summary logs on every invocation:
   - includes `policyMatched`, `mutationReason`, and `finalStatus`
   - improves operability when debug logging is not enabled
21. Hardened local Compose demo defaults for reliability:
   - switched demo Node images to `node:20-bookworm-slim`
   - added explicit injected-container OTLP endpoint/protocol
   - updated example docs to tail wrapper decisions from `docker.service`
22. Fixed env mutation edge case for empty placeholder values:
   - if an env var key exists with empty value, mutator now fills it with required injector value
   - previously, `preserve-if-present` logic could preserve empty values and skip effective injection
   - added unit test coverage for empty placeholder replacement

## Next Planned Steps

1. Evaluate selector extensions (image/env regex) only if env/annotation selectors are insufficient.
2. Consider exposing mutation decision metrics/counters for easier runtime diagnostics.
3. Add support docs for containerd/CRI integration after Docker path is stabilized.
4. Consider adding stable report schema versioning for long-term automation compatibility.

## How Future Agents Should Continue

1. Read this file first.
2. Read `ARCHITECTURE.md`.
3. Implement Phase 0 items before extending features.
4. Update this file after any architecture or behavior change.

## Change Log

- 2026-03-02: Initialized `pkg/ocihook` docs (`README.md`, `ARCHITECTURE.md`, `AGENTS.md`) and defined wrapper-based architecture.
- 2026-03-02: Implemented Phase 0 code (`config`, `oci_spec`, `policy`, `mutate`) and unit tests.
- 2026-03-02: Confirmed default behavior decisions for opt-in, `LD_PRELOAD` skip, `create`-only mutation, and OTEL var preservation.
- 2026-03-02: Implemented core Phase 1 runtime wrapper orchestration and unit tests.
- 2026-03-02: Added runtime entrypoint (`cmd/oci-runtime`), env-driven config, Docker integration docs, and Makefile build target.
- 2026-03-02: Added Phase 2 hardening features: dry-run mode, structured wrapper logging, delegate error wrapping, and local E2E recipe.
- 2026-03-02: Added policy fallback selector by OCI process env var for better plain-Docker compatibility.
- 2026-03-02: Added integration-style tests validating on-disk mutation persistence and dry-run non-persistence.
- 2026-03-02: Added host operations guide covering systemd env wiring, rollout, upgrade, and rollback.
- 2026-03-02: Added env-configurable wrapper log level and validation (`BEYLA_OCI_LOG_LEVEL`).
- 2026-03-02: Added machine-readable decision reporting (`BEYLA_OCI_DECISION_REPORT`) with wrapper report emission test coverage.
- 2026-03-02: Added docker-compose demonstration for OCI runtime wrapper behavior.
- 2026-03-02: Added one-shot bootstrap container assets for Linux host setup automation.
- 2026-03-02: Fixed OCI wrapper command detection when global flags precede `create` (critical for Docker/runc integration).
- 2026-03-02: Added runtime config file fallback and payload copy normalization for compatibility and easier recovery.
- 2026-03-02: Fixed OCI config round-trip field loss that caused `runc create` failures (`Cwd property must not be empty`).
- 2026-03-02: Added explicit OTEL exporter defaults in `ocihook` mutator and info-level wrapper decision summaries for easier diagnostics.
- 2026-03-02: Updated Compose demo defaults (glibc Node image + explicit OTLP endpoint/protocol) and documentation for wrapper decision log tailing.
- 2026-03-02: Fixed mutator behavior for pre-existing empty env vars so injector keys are not left blank.

## Current Operational Snapshot (2026-03-02)

This section captures the latest known runtime behavior from live host tests.

### Confirmed Working

1. Runtime wrapper can be invoked by Docker with `runtime=beyla`.
2. Direct runtime test produced mutation decision logs and decision report:
   - `policyMatched=true`
   - `mutated=true`
   - `finalStatus=delegated_with_mutation`
3. Injection mount path semantics are correct:
   - `LD_PRELOAD=/__otel_sdk_auto_instrumentation__/injector/libotelinject.so`
   - `OTEL_INJECTOR_CONFIG_FILE=/__otel_sdk_auto_instrumentation__/injector/otelinject.conf`
   - These must be container-internal paths (not `/var/lib/...` host paths).
4. OCI spec round-trip regression (`process.cwd` loss) was fixed earlier and container creation no longer fails with `Cwd property must not be empty`.

### Still Failing / Unclear

1. End-to-end telemetry verification is still inconsistent:
   - User reports no meaningful output in otel-collector logs.
2. Wrapper decision logs are inconsistent by execution path:
   - Visible in direct `docker run --runtime=beyla -e BEYLA_INJECT=true ...`
   - Often not visible for `docker compose` containers, even when inspect shows runtime `beyla`.
3. Therefore, there is still an unresolved environment/runtime-path mismatch between:
   - direct container run path
   - compose/containerd invocation path on this host.

### Most Recent Code Alignment Done

1. `pkg/ocihook/mutate.go` now sets explicit exporter env defaults, aligned with webhook behavior:
   - `OTEL_TRACES_EXPORTER=otlp`
   - `OTEL_METRICS_EXPORTER=otlp`
   - `OTEL_LOGS_EXPORTER=none`
2. `pkg/ocihook/runtime_wrapper.go` now emits info-level summary logs for every invocation (not only debug-level internals).
3. Demo compose switched to glibc Node image (`node:20-bookworm-slim`) and explicit OTLP endpoint/protocol on injected service.

### Fast Reproduction / Debug Checklist For Next Team

1. Rebuild and reinstall wrapper/bundle artifacts after latest source changes:
   - runtime binary
   - bootstrap image
   - payload copy into host instrumentation directory
2. Force-recreate demo containers:
   - `docker compose up -d --force-recreate`
3. Confirm host/runtime config:
   - `/etc/docker/daemon.json` contains runtime `beyla` with wrapper path
   - `/etc/beyla/oci-runtime.env` has expected `BEYLA_OCI_*` values
   - payload exists at `${BEYLA_OCI_HOST_INSTRUMENTATION_DIR}/${BEYLA_OCI_SDK_PACKAGE_VERSION}/injector/libotelinject.so`
4. Compare direct run vs compose behavior back-to-back:
   - direct: `docker run --rm --runtime=beyla -e BEYLA_INJECT=true node:20-bookworm-slim true`
   - compose injected service creation path
5. Tail docker service logs during both tests:
   - `sudo journalctl -u docker.service -f | grep -E 'ocihook.wrapper|policyMatched|mutationReason|finalStatus'`
6. Verify process env and mount in injected container:
   - `tr '\0' '\n' </proc/1/environ | grep -E 'LD_PRELOAD|OTEL_INJECTOR_CONFIG_FILE|BEYLA_INJECTOR_SDK_PKG_VERSION|OTEL_EXPORTER_OTLP_ENDPOINT|OTEL_TRACES_EXPORTER|OTEL_METRICS_EXPORTER|OTEL_LOGS_EXPORTER|BEYLA_INJECT'`
   - `ls -l /__otel_sdk_auto_instrumentation__/injector/libotelinject.so`

### Hypotheses To Validate Next

1. Compose path may not be invoking the exact same runtime argv/environment shape as direct run.
2. Compose containers may be short-circuiting expected mutation path due to non-obvious command differences.
3. Collector pipeline may receive no application telemetry because auto-instrumentation still does not successfully initialize inside target process despite env injection.
