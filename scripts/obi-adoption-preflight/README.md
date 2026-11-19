# Exact-SHA OBI adoption controller

This local implementation extends the exact-SHA read-only collector into a daily single-writer path in `.github/workflows/bot_sync-obi-submodule.yml`. It replaces that workflow's weekly scheduled entry with a daily run; it does not add a second writer. The separate 15-minute fork synchronization is unchanged. Before merging, owners must coordinate the schedule cutover and publication-policy approval: repository variable `OBI_ADOPTION_WRITER_ENABLED` defaults off/unset here, so the local workflow can only publish a new draft after separate authorization. If merged unset, the daily cron still replaces the old weekly cron; it does not preserve the former weekly writer. The default-off state does not disable status-only updates to an already-managed PR. `OBI_ADOPTION_REPAIR_ENABLED` is a separate default-off gate for repair reservations and worker pushes; both flags must be explicitly enabled for repair. Changing a repository variable is not an instantaneous cancellation mechanism; an in-flight workflow may still complete actions already authorized, so owners must inspect/cancel runs as needed. No workflow was dispatched, and these local changes have not been pushed or activated.

The collector samples one immutable upstream `main` commit (`U`), reads Beyla's `.obi-src` pin (`P`) from the workflow snapshot and current Beyla main (`B`), checks complete ancestry and exact-U reachability from Grafana's OBI fork, calculates the conservative oldest committer-age proxy, and inventories same-base open pin PRs plus bounded exact/short-SHA history. The proxy is a commit-age heuristic, not true upstream-availability lag; it is neither an adoption blocker nor release authorization. Quiet upstream does not block.

Only a complete, current, consistent source snapshot with no active/rejected conflict can select `create`. An existing PR for another target is preserved and defers a new candidate; a same-target managed PR is observed, never regenerated over. The update remains one atomic candidate containing `.obi-src=U` and the generated/vendor/compatibility changes. The optional `source_pr`/`source_sha` inputs are paired exact values and revalidated; daily sampling needs neither. Fork-behind retry is bounded and keeps the original `U`.

Candidate generation occurs without write credentials and does not execute in the publisher. A trusted API publisher validates the artifact/path scope, rechecks main/source/fork/open-PR facts, builds a signed commit, requires GitHub's `verification.verified` response, creates only the exact managed branch (never updates an existing ref), then creates a draft PR. Human review and merge are required. Existing same-target PRs are only reconciled through the canonical status/budget helper; deadline reconciliation does not start repair. Repair is separately gated by `OBI_ADOPTION_REPAIR_ENABLED` and the writer flag, both of which require owner authorization. No auto-merge, release, deployment, upstream write, or reviewer request is enabled by this workflow.

This is an incremental implementation, not a completed operations rollout. Before enabling/dispatching it, review the resulting PR, verify GitHub App signing behavior and permissions, confirm team publication policy, and inspect the actual supervisor/fixer side-effect exclusions and credentials split. The supervisor/fixer changes and canonical status/budget helper are included in this unpublished local revision. Legacy rejected-SHA discovery uses bounded GitHub search in addition to the exact managed-branch query; the search is not a proof of complete historical coverage, so unknown/truncated inventory must block publication.

## Local checks

From the Beyla repository root:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_obi_adoption*.py'
python3 -m py_compile scripts/obi-adoption-preflight/*.py
actionlint .github/workflows/bot_sync-obi-submodule.yml .github/workflows/obi-adoption-preflight.yml
```
