# Architecture: OCI Runtime Wrapper Injection

## 1. Scope

Build a host-level injection mechanism for plain Docker/container runtime environments by porting the mutation behavior from the Kubernetes webhook model to OCI runtime spec mutation.

## 2. Design Principles

- Minimize runtime coupling by delegating to an existing OCI runtime.
- Keep mutation logic deterministic and idempotent.
- Reuse existing Beyla injection semantics where possible (env vars, SDK package versioning, language enable/disable knobs).
- Fail safe: if injection cannot be safely applied, continue without mutating unless strict mode is enabled.

## 3. High-Level Architecture

### 3.1 Components

- `Runtime Wrapper`:
  - Binary: `beyla-oci-runtime` (name tentative).
  - Role: CLI-compatible front for OCI runtime commands.
  - Core responsibility: intercept `create`/`run` paths and mutate OCI spec before delegating.

- `Spec Loader`:
  - Resolves bundle path (`--bundle`, default CWD).
  - Reads `config.json` into OCI runtime-spec struct.

- `Policy Engine`:
  - Decides whether a container should be instrumented.
  - Inputs: OCI annotations, process env, rootfs path, image references from annotations (runtime-dependent), optional allow/deny rules.

- `Spec Mutator`:
  - Injects bind mount(s) for SDK/injector payload.
  - Injects environment variables (`LD_PRELOAD`, `OTEL_*`, `BEYLA_INJECTOR_SDK_PKG_VERSION`, language toggles).
  - Applies idempotency checks.

- `Delegate Executor`:
  - Executes real OCI runtime (`runc` or configured delegate) with original args.

- `Observability`:
  - Structured logs for decision, mutation result, and delegation outcome.
  - Optional dry-run mode to report proposed mutations without applying.

### 3.2 Data Flow

1. Docker/containerd invokes `beyla-oci-runtime <cmd> ...`.
2. Wrapper parses command and bundle path.
3. For mutating commands (`create`, potentially `run`):
   - Load OCI `config.json`.
   - Evaluate policy.
   - If matched, mutate spec and atomically persist updated `config.json`.
4. Delegate to real runtime with same command/args.
5. Return delegate exit code.

## 4. Mutation Model

### 4.1 Environment Variables

Inject baseline variables aligned with webhook behavior:

- `BEYLA_INJECTOR_SDK_PKG_VERSION`
- `LD_PRELOAD`
- `OTEL_INJECTOR_CONFIG_FILE`
- `OTEL_EXPORTER_OTLP_ENDPOINT`
- `OTEL_EXPORTER_OTLP_PROTOCOL`
- `OTEL_SEMCONV_STABILITY_OPT_IN`
- Optional exporter/sampler/propagator variables
- Language toggles for enabled/disabled SDK families

### 4.2 Mounts

Inject read-only bind mount for instrumentation payload:

- Host path example: `/var/lib/beyla/instrumentation/<sdk_version>`
- Container path example: `/__otel_sdk_auto_instrumentation__`

### 4.3 Idempotency Rules

Skip mutation if any of the following hold:

- Existing `LD_PRELOAD` points to non-Beyla injector.
- Existing `OTEL_INJECTOR_CONFIG_FILE` indicates previous injection.
- Existing `BEYLA_INJECTOR_SDK_PKG_VERSION` matches configured version.

## 5. Compatibility Model

### 5.1 Target Environments

- Docker Engine on Linux host (primary).
- containerd with runtime wrapper integration (secondary).
- CRI-O support can be evaluated later.

### 5.2 Integration Strategy

- Register runtime in Docker daemon (`daemon.json`) as custom runtime path.
- Start selected containers with `--runtime=<wrapper>`.
- Keep `runc` as delegate runtime.

## 6. Security and Safety

- Wrapper must run with same privileges as runtime invocation context.
- Mutations must not widen container privileges by default.
- Preserve user-provided env vars unless explicitly overridden by policy.
- No network dependency in critical path.

## 7. Failure Handling

Modes:

- `permissive` (default): log and continue without mutation on non-fatal errors.
- `strict`: fail container creation if expected mutation cannot be applied.

Errors considered non-fatal in permissive mode:

- Bundle not found for non-mutating commands.
- Missing optional metadata for policy matching.

Errors considered fatal:

- Delegate runtime missing/unexecutable.
- Corrupted OCI spec when mutation is requested.

## 8. Reuse from Existing Webhook

Candidate reuse from `pkg/webhook`:

- Env var naming and OTEL exporter/sampler/propagator semantics.
- SDK enable/disable by language.
- Version tagging concepts (`BEYLA_INJECTOR_SDK_PKG_VERSION`).

Not directly reusable:

- Kubernetes metadata-based selectors.
- Pod/deployment restart behavior.
- AdmissionReview/JSONPatch machinery.

## 9. Proposed Package Layout

```text
pkg/ocihook/
  README.md
  ARCHITECTURE.md
  AGENTS.md
  config.go            # wrapper + injection config schema
  runtime_wrapper.go   # CLI entry and delegate execution
  oci_spec.go          # bundle/spec load/store helpers
  policy.go            # selection logic
  mutate.go            # spec mutation (env + mounts)
  mutate_test.go
  policy_test.go
```

## 10. Phased Implementation Plan

### Phase 0: Architecture + Skeleton

- Define interfaces and config model.
- Add unit-testable mutator with sample OCI specs.

### Phase 1: Minimal Functional Wrapper

- Support `create` and `run` commands.
- Inject mount + core env vars.
- Delegate to `runc`.

### Phase 2: Policy and Safety Hardening

- Include allow/deny policy selectors.
- Idempotency checks and strict/permissive modes.
- Better logging and dry-run mode.

### Phase 3: Operationalization

- Docker integration documentation.
- E2E tests in a local Docker host test harness.

## 11. Open Decisions

1. Container selection source of truth for non-Kubernetes hosts:
   - OCI annotations only, or a richer policy file?
2. Default behavior when `LD_PRELOAD` already exists:
   - skip, prepend, or fail?
3. Should mutation happen on both `create` and `run`, or only `create`?
4. How strict should env var override behavior be versus existing user values?

## 12. Initial Recommendation

- Mutate on `create` only.
- Default to `permissive` mode.
- Skip when non-Beyla `LD_PRELOAD` is present.
- Keep policy simple in v1: explicit opt-in by annotation or runtime flag.
