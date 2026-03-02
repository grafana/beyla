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
