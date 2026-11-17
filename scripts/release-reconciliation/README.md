# Read-only release reconciliation

This helper summarizes release-related GitHub facts for human review. It does not
select a release version, gate or trigger a release, or persist train state.

## Current workflow

The GitHub Actions workflow runs daily at 14:00 UTC and can also be started
manually. It collects paginated GitHub API responses into a temporary directory,
validates them with `load_facts`, and publishes a bounded JSON report in the
workflow summary. It requires only read access to repository contents and
Actions.

The daily run is an observation schedule; publication cadence is evaluated
weekly. Neither schedule is a release trigger or gate. The report may flag
prerelease-only observations for policy review; owners still need to decide
whether prereleases qualify. No release version is selected.

## Data flow and ownership

GitHub is the authoritative store for release refs, workflow runs, releases,
deployment outcomes, and approvals. The report is derived from a point-in-time
read of those facts. It is emitted to the Actions run log and human-readable
workflow summary; neither is durable release truth, and normal Actions run
retention applies. Grot may be configured separately as a consumer to explain
or investigate the report and notify people. It is not an execution engine,
checkpoint, or resume store, and this repository does not configure or verify
that integration.

| Where | Writer | Reader | Meaning |
|---|---|---|---|
| GitHub refs, Actions runs, releases, deployment and approval records | Existing GitHub workflows and authorized operators | Reconciliation workflow and maintainers | Authoritative current facts; future progression gates must inspect these facts. |
| Reconciliation JSON in the run log and workflow summary | Read-only reconciliation workflow | Maintainers; optionally a separately configured Grot consumer | Derived, disposable observation snapshot; never a command or resume checkpoint. |

The operational data flow is therefore: (1) GitHub records release facts; (2)
the scheduled or manually started workflow reads and summarizes those facts;
(3) maintainers inspect the human summary, while an optional external consumer
may explain or investigate the marked JSON and notify people; and (4) any
future Actions progression re-reads GitHub's current facts and applies explicit
gates. It does not deserialize an old report to decide where to resume.

The workflow does not notify Grot or Slack. Its summary is not durable train
state. The current implementation is read-only; the architecture below is a
proposal, not functionality delivered by this workflow.

### Log integration contract

The report step emits the JSON exactly once between two case-sensitive marker
lines: `BEGIN_RELEASE_RECONCILIATION_REPORT` and
`END_RELEASE_RECONCILIATION_REPORT`. An external log consumer can use these
stable delimiters to extract the enclosed JSON; the Actions run log may add its
normal step prefixes to displayed lines. The workflow summary remains intended
for human reading and does not carry these markers. This repository defines the
output contract only; external integrations and delivery are configured and
verified separately. The marker contract does not imply that a notification
was sent or that any release action occurred.

## Target architecture {#target-architecture}

The proposed target is an Actions-owned lifecycle that reuses existing public
release workflows behind their exact candidate gates. In sequence, it would:

1. Select the weekly Beyla candidate and resolve its source revisions.
2. Prepare the paired Beyla and OBI release branches.
3. Wait for branch CI and stop on failures or ambiguous results.
4. Create the prerelease/tag and artifacts through existing workflows.
5. Deploy the release to development.
6. Deploy to operations and validate it there.
7. Promote the release to stable/latest.
8. Deploy the stable release to production.
9. Follow up on Alloy; an Alloy PR may be prepared once the release is
   available, but should be merged only after stable.

Daily checks observe release and CI facts; the weekly publication cadence is
distinct from those checks. Completion events can wake reconciliation, but
GitHub remains authoritative. Candidate selection, health criteria, approvals,
and prerelease policy remain maintainer decisions, not guarantees enforced by
these workflows; this target does not promise unconditional publication. The
current workflow above remains read-only and does not implement this lifecycle.

## Local checks

Run the deterministic helper tests with:

```sh
python3 -m unittest discover -s scripts/release-reconciliation -p 'test_*.py'
```
