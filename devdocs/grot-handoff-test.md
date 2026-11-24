# Grot handoff workflow test

These two GitHub Actions workflows are an isolated, no-op fixture for checking
the proposed readiness-to-human-approval handoff. They do not publish a release,
deploy, access secrets, request an OIDC token, check out source, or call external
actions. The readiness report is explicitly marked test-only and contains no
release facts. The second workflow is triggered only by a successful completion
of the named readiness workflow on `main`, from this same repository, and pauses
at the `grot-handoff-test` environment before its no-op echo step.

**Do not dispatch the readiness workflow until the environment's required
reviewer has been configured and verified.** Referencing an environment in a
workflow can cause GitHub to create it without protection. Before testing:

1. In repository settings, create/configure `grot-handoff-test` with the intended
   required reviewer, and verify the protection rule is active.
2. Confirm the readiness workflow is enabled and Grot's exact workflow trigger
   is configured separately by an authorized owner.
3. Only after those checks, set repository variable
   `GROT_HANDOFF_TEST_ENABLED` to `true`. It is absent/false by default, so both
   the report job and the downstream approval job are gated off until explicit
   opt-in.
4. Manually dispatch **Grot handoff readiness test** on `main`. Verify the
   test-only report, successful completion, Grot event delivery, and the child
   workflow's pending required-reviewer approval. Approve only the test run and
   verify the no-op child resumes with its run-correlation links.
5. Disable the variable after testing. Remove the environment and any associated
   test deployment record using the repository's approved cleanup procedure.

No environment, variable, Grot setting, or workflow run is created by this PR.
End-to-end behavior remains untested until the prerequisites above are met.
