# Root cause analysis and implementation plan

**Triggering PR**: #{{PR_NUMBER}} — "{{PR_TITLE}}"

## Process

1. **Read `triage.md`** first — it is your sole source of CI failure context. Do not download CI logs or artifacts; triage has already extracted the relevant errors. Triage does not compare OBI test inputs or diffs. That comparison is yours, using the SHAs in `triage.md`.
2. **Identify what changed in OBI**: Triage will include old and new OBI submodule SHAs. Run `git -C .obi-src log OLD_SHA..NEW_SHA --oneline` and targeted diffs (`git -C .obi-src diff OLD_SHA..NEW_SHA -- <file>`) to see exactly what OBI changed. OBI CI passes upstream and Beyla main is stable, so **breaking changes come from these new OBI commits and/or updated vendor packages on the branch**. This OBI diff is the primary input for root cause analysis.
3. **Analyse root causes** by cross-referencing the OBI changes with triage findings and Beyla source code. Look for a **common issue** affecting multiple workflows to minimise the number of changes needed.
4. **Cross-reference symbol changes**: When OBI renames, removes, or changes the signature of an exported symbol (function, type, const, struct field), search the Beyla codebase for **all references** to that symbol — including test files, helper packages, and generated test scripts. List every call site that needs updating. Existing tests may reference removed or renamed symbols and must be updated in the plan alongside production code.
5. **Write `plan.md`** with a clear, ordered implementation plan.

**Stay under ~25 tool calls.** Read triage.md, then open only the minimal set of source files needed to form the plan. Do not explore the repo broadly. Do not spawn subagents. Do the field-by-field comparison yourself in this step. `plan.md` must contain the resulting edits, not an instruction for the implement job to repeat the comparison.

## Deductive reasoning — where changes MUST be

OBI CI passes for the submodule commit used in this branch. Beyla main CI passes. Therefore, the **only** places that can need changes are:
- **Beyla's own Go code** (not in `vendor/`, not in `.obi-src/`)
- **Test synchronisation rules** in `scripts/generate-obi-tests.sh` (BEHAVIORAL_TRANSFORMS, CODE_INJECTIONS)
- **Beyla-specific test extensions** in `internal/test/beyla_extensions/`

**NEVER plan changes to `vendor/` or `.obi-src/`.** Those directories contain OBI code; if OBI CI passes, the code is correct by definition.

## Diagnostic patterns

**Test failures — sync before patch:**
When a Beyla test fails on an assertion, **do not** simply adjust the assertion to make it pass. First, locate the corresponding test in OBI (`.obi-src/`) and compare the failing test block with its upstream version:
- If the test block (or the specific sub-case / table entry within it) has been **removed** in OBI, the correct fix is to **remove the same block** from Beyla's copy of the test (applying the OBI→Beyla translation rules from `scripts/generate-obi-tests.sh`). Do not patch the assertion.
- If the test block still exists in OBI but the assertion is now wrong (e.g., a changed return value or behaviour), **then** adjust the assertion to match the new OBI behaviour.
The general principle is: Beyla's generated tests shadow OBI's tests. When OBI changes a test, Beyla's version should be updated to match — not worked around with a minimal assertion fix that hides the upstream intent.
- If OBI **added new test inputs** (e.g., new YAML config fields, setup data, table-test entries), the correct fix is to port those same inputs into Beyla's version of the test. An assertion that fails because of a missing input must be fixed by adding the input, not by changing the expected value to match Beyla's current (wrong) default.

**Anti-pattern — assertion-only fix**: If your plan only changes assertion values without also porting the corresponding OBI test inputs or production code changes, re-examine. The goal is to port OBI's intention and implementation pattern into Beyla, not to minimally satisfy test assertions. Example: OBI adds `log_format: json` to a test config YAML and asserts `LogFormat: LogFormatJSON`. The wrong fix is setting the assertion to the default (`LogFormatText`). The right fix is adding `log_format: json` to Beyla's test config, matching OBI's upstream intention.

**Config struct parity (most common cause of timeouts):**
Beyla mirrors OBI config structs and uses `pkg/helpers/config/convert.go` (`Convert()`) to copy between them. This converter **panics if the destination struct has an exported field the source does not have**. When OBI adds new config fields, Beyla's mirror must be updated with matching fields (`BEYLA_`-prefixed env tags, matching defaults). A startup panic in k8s-cache manifests as **test timeouts** — the cache process is dead and Beyla never receives K8s metadata, so tests hang rather than showing a panic.

**Backport OBI's config-v2-only settings to Beyla v1.** OBI tags some settings `yaml:"-" env:"-" jsonschema:"-" validate:"-"` because its own v1 loader does not expose them; config v2 writes them in code. That is not how Beyla works. Do not copy those skip tags onto a user-facing Beyla field.

Recreate the struct in a Beyla package. Keep the same exported field names so `FromOBI` and `AsOBI` copy it onto the OBI type by name, including nested structs whose Go types differ. Give every user setting a v1 `yaml` name and a `BEYLA_`-prefixed `env` tag. The reference is `pkg/beyla/name_resolver.go`: OBI's `GCE` and `Azure` fields are `yaml:"-" env:"-"`, and Beyla's `NameResolverConfig` exposes them with `BEYLA_NAME_RESOLVER_GCE_*` and `BEYLA_NAME_RESOLVER_AZURE_*`. `pkg/beyla/peer_metadata.go`, `pkg/beyla/logs_config.go`, and `pkg/beyla/exceptions_config.go` do the same for peer metadata, exception logs, and exception capture.

Include every exported field of the OBI struct. Runtime hooks that are not user settings (`LogsExport`, `InjectHeaders`, and the same kind of func field) stay on the Beyla struct with the same name and type, tagged `yaml:"-" env:"-"`, so a v2 document still round-trips through `FromOBI` and `AsOBI`. Omitting them makes `AsOBI` panic or drops the hook.

A bool or string that already lives on a Beyla struct does not need a new type. `Attributes.SanitizeSQLQueryText` is the reference: replace the skip tags with a yaml name and a `BEYLA_` env tag.

Keep skip tags, and list the field in `FromOBI`'s skip map, only for values that are not configuration: the cached `obi` config, and the Alloy `TracesReceiver`. Do not leave a newly ported feature unreachable from a v1 file.

Known mirror pairs — check these first:
- `vendor/.../obi/pkg/kube/kubecache/config.go` (OBI) ↔ `cmd/k8s-cache/cfg/config.go` (Beyla)
- `vendor/.../obi/pkg/obi/config.go` (OBI) ↔ `pkg/beyla/config.go` (Beyla), bridged via `pkg/beyla/config_obi.go`

To diagnose: compare every exported field in the OBI config struct against the Beyla mirror. Any mismatch will cause a panic at startup.

**Timeouts:** First check config struct parity (above). Then look for container crashes (panics, CrashLoopBackOff) in triage. A timeout waiting for data usually means a sidecar crashed on startup.

**RCU CPU stalls** in VM workflows are a known occurrence — note them but do not plan fixes unless there is a clear code cause.

**Stuck waits:** Tests waiting for metric/cache expiry that never occurs — investigate config, timeout values, or broken expiry logic in Beyla source.

## Scope

Port changes from OBI into Beyla. Do not plan edits to `internal/testgenerated/` (generated); plan changes to `scripts/generate-obi-tests.sh` or Go source instead. No test skipping — address failures at the source. Recommend upstream (OBI) changes if needed; code injections are a last resort.

## Output

Single file **`plan.md`** in repo root with:
1. **Summary**: Short description of failures and the common root cause(s) identified.
2. **Changes**: Ordered list of concrete file edits in Beyla only. Every item names a file path, the code to add or delete, and why. A step that says "audit", "re-verify", "confirm parity", or "if this fails, investigate" is not done — replace it with the edit, or drop it.
3. **Verification**: only commands from this list, and only the ones that apply:
   - `make fmt`
   - `make lint`
   - `go vet` of the packages you changed
   - `go test` of the packages you changed, with no integration build tag
   - `./scripts/generate-obi-tests.sh` then `git diff --exit-code internal/testgenerated/`

Do not tell the implement job to run integration tests, `make integration-test`, Docker, `diff`, or the `beyla` binary. That job has a 100-turn cap and a shell allowlist; those commands are what made it fail with `error_max_turns` before it could commit. Keep the plan to the smallest set of edits that address the common root cause.

No code changes. Only produce `plan.md`.
