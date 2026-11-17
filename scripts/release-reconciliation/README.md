# Read-only release reconciliation

Run the same read-only collector used by CI locally:

```sh
mise run release:reconcile
```

Requirements: Mise, `gh` authenticated for read-only GitHub API access, `jq`,
and Python 3. `REPOSITORY=owner/name` can select a repository explicitly;
otherwise `gh repo view` determines it from the current directory. Set
`GH_TOKEN` directly or use `gh auth login`.

The task reads the `main` candidate commit and its pinned `.obi-src` SHA,
prepare/tag workflow runs, releases, and paired `release-` refs. It does not
read deployment/approval records, select a version, change GitHub state, or
persist release state. API failures and malformed facts are reported as
unknown, not treated as success. Output is deterministic JSON between the
case-sensitive `BEGIN_RELEASE_RECONCILIATION_REPORT` and
`END_RELEASE_RECONCILIATION_REPORT` lines. In Actions, the same JSON is also
appended to the step summary; the markers are for log consumers, not the
summary. The report is an observation snapshot, not a resume checkpoint.

Run the helper tests with:

```sh
python3 -m unittest discover -s scripts/release-reconciliation -p 'test_*.py'
```
