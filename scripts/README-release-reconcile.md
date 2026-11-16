# Read-only release reconciliation

Run the deterministic helper tests locally with:

```sh
python3 -m unittest scripts/test_release_reconcile_report.py
```

The GitHub Actions workflow collects paginated GitHub API responses to a
temporary directory, validates them with `load_facts`, and publishes a bounded
JSON report in the workflow summary. It requires read-only `contents` and
`actions` permissions. The workflow runs daily at 14:00 UTC, while publication observations remain
weekly; neither gates nor triggers releases. Owners still need to define
whether prereleases qualify. No release version is selected.

This workflow does not notify Grot or Slack. Its summary artifact is not durable
train state, and no wake-up/result bridge has been configured or verified.
