# Implement fixes from plan

**Triggering PR**: #{{PR_NUMBER}} — "{{PR_TITLE}}"

Triage and root cause analysis are already complete. Your only job is to **implement the plan and push**. Do not re-triage, re-analyse failures, download CI logs, or download artifacts.

## Inputs

- **`plan.md`** (repo root) — your implementation spec. Apply the concrete file edits. Skip any step that is only diagnostic: "audit", "re-verify every field", "confirm parity", "reproduce locally", or "if this fails, investigate".
- **`triage.md`** (repo root) — reference only if plan.md directs you to it for additional context.
- Source code as needed, including `.obi-src/` for reference when porting OBI changes.

## Verification principle

Before committing any test fix, verify that it ports OBI's upstream intention, not just makes the test pass. For each changed test file:
1. Open the corresponding OBI test in `.obi-src/` and compare both the **test inputs** (config YAML, setup data, table entries) and the **assertions**.
2. If OBI added new inputs that drive the assertion, those inputs must appear in Beyla's version too. An assertion-only change that omits the upstream input change is incorrect — it makes the test pass against the wrong behavior.

## Forbidden directories — never modify

- **`vendor/`** — vendored OBI code; correct by definition if OBI CI passes.
- **`.obi-src/`** — the OBI submodule.
- **`internal/testgenerated/`** — generated output; change scripts or extensions instead.

## Turn budget

This job fails at 100 turns. The last run died that way (`error_max_turns`, 14 permission denials) before it committed. Finish in one pass.

- Do not spawn subagents. `Task` is not available.
- Do not re-diagnose the CI failure, download logs, or download artifacts.
- If a shell command is denied, stop using it. Do not retry it, and do not wrap it in `bash -c` or `sh -c`.
- Do not start long-running processes. Never run `make integration-test`, Docker, `go test -tags integration`, or the `beyla` binary. CI runs those after you push.
- If `plan.md` tells you to run those, or to run `diff` or launch `./bin/beyla`, skip that instruction.

## Shell commands you may run

Anything else is denied.

- `git diff`, `git status`, `git log`, `git show`, `git rev-parse`
- `git -C .obi-src ...` for read-only inspection of the submodule
- `go test`, `go vet`, and `go build` for packages you edited, without an integration build tag
- `make fmt`, `make lint`, `make generate-obi-tests`, `make generate-config-schema`, and `make check-config-schema`, each as its own command
- `./scripts/generate-obi-tests.sh`
- `gh pr comment {{PR_NUMBER}} --body "..."` once, after the commit
- `cat`, `ls`, `grep`, `head`, `tail`, `pwd`, `jq`, `sort`, `uniq`, `wc`, `python3`, `echo`, `date`

## Commit

Commit with `mcp__github_file_ops__commit_files` only. Files must already be saved locally. Do not `git add`, `git commit`, or `git push`. There is no comment MCP tool and no `create_or_update_file` tool; a denied or missing tool is not a reason to keep trying.

## Process

1. Read `plan.md` and make the concrete edits.
2. Run the quick checks above that match the files you changed. After a generator change, run `./scripts/generate-obi-tests.sh` and `git diff --exit-code internal/testgenerated/`. After a Beyla config struct, yaml tag, or env tag change, run `make generate-config-schema` and then `make check-config-schema`. Commit the updated `docs/config-schema.json`. `make check-config-schema` fails if that file is left stale.
3. Call `mcp__github_file_ops__commit_files` with those files and a short message. Then one `gh pr comment {{PR_NUMBER}}` summarising the files, the fix, and any upstream OBI follow-up from the plan. Then stop.

## Rules

- Do not skip or disable tests — fix the underlying cause.
- Prefer porting proper fixes from OBI into Beyla over code injections in `scripts/generate-obi-tests.sh`.
- Do not copy `yaml:"-" env:"-"` onto a Beyla setting just because OBI marked it config-v2-only. Recreate the struct with v1 yaml names and `BEYLA_` env tags, as `pkg/beyla/name_resolver.go` does, so `FromOBI` and `AsOBI` convert it by field name. Keep skip tags for function hooks, the cached `obi` config, and the Alloy traces receiver. When a hook exists on the OBI struct, keep it on the Beyla struct so the round trip does not drop it.
- After that config change, regenerate `docs/config-schema.json` with `make generate-config-schema` and confirm it with `make check-config-schema`. CI runs the check and fails when the committed schema is stale.
- Read-only git for inspection. Do not force-push or change the submodule pointer.
