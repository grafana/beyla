# OBI adoption repair worker: security and enablement gates

The reusable worker is callable only by the trusted `supervisor_rerun-flaky.yml`
workflow on `main` for a completed failing `pull_request` run. It re-reads the
managed draft PR, current `main`, `.obi-src` target, bot-owned status reservation,
and trigger run before proposing and again before publishing. The model call is
the Anthropic Messages API with a fixed Sonnet model and no tools. The API key is
available only in the trusted proposal job; no candidate source is executed in
that job. Candidate Go code is tested in a separate job with no secret, OIDC,
or repository-write permission. The publisher consumes only the bounded
manifest artifact, verifies its digest and file blob preconditions, rechecks
the PR/base/target/reservation, and requires a GitHub-verified commit before a
non-force branch update. It does not comment, change draft state, request
reviewers, merge, or dispatch release work.

## Runtime enablement checks

The reusable workflow and trusted CLI fail closed unless both repository
variables `OBI_ADOPTION_WRITER_ENABLED` and `OBI_ADOPTION_REPAIR_ENABLED` are
exactly `true`. Keep repair disabled while piloting initial draft PR creation;
turning on the writer alone does not authorize model calls or repair commits.

Before enabling repair calls on a live managed PR, verify the effective
permissions of the existing Vault-backed `grafana-beyla-bot` token using the
`default` permission set for this repository. The pinned shared action accepts
`github_app`, `permission_set`, and `vault_instance`; it does not accept
per-permission `permission-*` inputs. This worker requests no new Vault
permission set and does not claim that `default` is contents-only. Confirm that
the token's effective repository scope is sufficient for `contents:write` and
does not grant unintended access; configure a narrower existing Vault set in a
separately authorized infrastructure change if available.

The publisher stops before updating the branch unless the GitHub REST commit
response reports `verification.verified == true`. Confirm that the deployed App
installation produces a verified signature under this endpoint before enabling
the writer. No live write is used for this check. If the response is unverified,
the workflow must report blocked; do not remove the signature check or switch to
an unsigned commit path. The initial updater and repair worker must both use the
same short `obi-adoption-writer` lock and the same compare-and-swap head/base
checks.
