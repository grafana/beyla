---
applyTo: "cmd/**/*.go,pkg/**/*.go,internal/**/*.go,scripts/generate-obi-tests.sh"
---

# OBI Integration Instructions

When working on or reviewing changes related to OBI (OpenTelemetry eBPF Instrumentation) integration in Beyla, follow these rules strictly.

## Forbidden directories

Never modify files in these directories directly:
- `vendor/` — vendored OBI code, managed by `go mod vendor`. If OBI CI passes, this code is correct by definition.
- `.obi-src/` — the OBI submodule. Changes go upstream.
- `internal/testgenerated/` — generated test output. Change `scripts/generate-obi-tests.sh` or Go source instead.

## Config struct parity

Beyla mirrors OBI config structs and uses `pkg/helpers/config/convert.go` (`Convert()`) to copy between them. This converter panics if the destination struct has an exported field the source does not have (and vice versa).

When OBI adds new config fields, Beyla mirrors must be updated with matching fields, including `BEYLA_`-prefixed env tags and matching defaults.

Known mirror pairs:
- `vendor/.../obi/pkg/kube/kubecache/config.go` (OBI) <-> `cmd/k8s-cache/cfg/config.go` (Beyla)
- `vendor/.../obi/pkg/obi/config.go` (OBI) <-> `pkg/beyla/config.go` (Beyla), bridged via `pkg/beyla/config_obi.go`

A config mismatch causes a startup panic. In k8s-cache this manifests as test timeouts — the cache process is dead and Beyla never receives K8s metadata, so tests hang rather than showing a panic.

## Test sync before patch

When a Beyla test fails on an assertion, do not simply adjust the assertion to make it pass. First locate the corresponding test in OBI (`.obi-src/`) and compare:
- If the test block or sub-case has been **removed** in OBI, remove the same block from Beyla's copy (applying the OBI-to-Beyla translation rules from `scripts/generate-obi-tests.sh`). Do not patch the assertion.
- If the test block still exists in OBI but the assertion changed, then adjust the assertion to match the new OBI behaviour.

Beyla's generated tests shadow OBI's tests. When OBI changes a test, Beyla's version should be updated to match — not worked around with a minimal assertion fix that hides the upstream intent.

## Port over inject

Prefer porting proper fixes from OBI into Beyla code over adding code injections in `scripts/generate-obi-tests.sh`. Code injections are a last resort.

## No test skipping

Do not skip, disable, or `t.Skip()` tests. Fix failures at the source.

## Scope of OBI integration changes

Changes should be limited to:
- Beyla's own Go code (not in `vendor/`, not in `.obi-src/`)
- Test synchronisation rules in `scripts/generate-obi-tests.sh` (`BEHAVIORAL_TRANSFORMS`, `CODE_INJECTIONS`)
- Beyla-specific test extensions in `internal/test/beyla_extensions/`

When reviewing OBI integration changes, flag modifications to forbidden directories, test skips, assertion patches that do not match upstream OBI test changes, and config struct mismatches.
