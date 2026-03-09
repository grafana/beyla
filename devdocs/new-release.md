# Beyla Release

## Overview

Beyla embeds OBI as the `.obi-src` git submodule.
The release process follows a weekly release train and Semantic Versioning only:

- Version format: `vMAJOR.MINOR.PATCH`
- No RC suffixes
- `MINOR` bumps for each weekly train slot
- `PATCH` bumps when multiple releases are needed in the same week
- `MAJOR` bumps only for breaking Go API changes
- Failed/abandoned versions are skipped (no retroactive patching)

Releases move through environments: `dev -> ops -> prod`.
A version starts as a prerelease and is promoted to stable/latest only when it graduates.

## Automation Workflows

- `bot_sync-obi-fork.yml`: continuously syncs Grafana OBI fork main with upstream.
- `bot_sync-obi-submodule.yml`: weekly (Monday) update of Beyla `.obi-src` on `main`.
- [`release-train-prepare.yml`](../.github/workflows/release-train-prepare.yml): cuts/updates OBI and Beyla release branches and regenerates artifacts.
  - Manual dispatch after OBI fork is synced.
- [`release-train-tag.yml`](../.github/workflows/release-train-tag.yml): creates SemVer tags and prereleases in OBI and Beyla.
  - Manual dispatch after release branch CI is green.
- [`promote-patch-to-stable.yml`](../.github/workflows/promote-patch-to-stable.yml): marks a prerelease as stable/latest and promotes Docker tags.

## End-to-End Flow

### 1. Preconditions

- OBI fork is synced from upstream.
- Beyla `main` is synced to latest intended OBI state.
- CI on Beyla `main` is green.

### 2. Prepare release branches

Run [`release-train-prepare.yml`](https://github.com/grafana/beyla/actions/workflows/release-train-prepare.yml).

Inputs:

- `version` (optional): explicit `vMAJOR.MINOR.PATCH`.
- `bump`: `auto` / `minor` / `patch` (used when `version` is empty).
- `dry_run` (optional).
- `skip_ci_check` (optional).
- `skip_upstream_sync_check` (optional).

What it does:

1. Resolves the OBI SHA pinned by Beyla `main`.
2. Creates/updates OBI branch `release-vX.Y.Z` from that SHA.
3. Runs OBI artifact generation (`make docker-generate`, `make java-build`) and pushes branch changes.
4. Creates/updates Beyla branch `release-vX.Y.Z` from Beyla `main`.
5. Points `.obi-src` to OBI `release-vX.Y.Z`.
6. Runs Beyla artifact generation (`make vendor-obi`, `make java-build`) and pushes branch changes.

### 3. Wait for release branch CI

Ensure both release branches are green:

- `grafana/opentelemetry-ebpf-instrumentation:release-vX.Y.Z`
- `grafana/beyla:release-vX.Y.Z`

### 4. Create tags and prereleases

Run [`release-train-tag.yml`](https://github.com/grafana/beyla/actions/workflows/release-train-tag.yml) with `version=vX.Y.Z`.

Inputs:

- `version` (required).
- `dry_run` (optional).
- `skip_ci_check` (optional).

What it does:

1. Verifies both `release-vX.Y.Z` branches exist (and are green unless skipped).
2. Creates tag `vX.Y.Z` in OBI and Beyla at release branch heads.
3. Creates prereleases in OBI and Beyla for `vX.Y.Z`.

### 5. Promote to stable/latest

When the release train has validated a version in `prod`, run:

- [`promote-patch-to-stable.yml`](https://github.com/grafana/beyla/actions/workflows/promote-patch-to-stable.yml) with `version_tag=vX.Y.Z`.

This marks the Beyla GitHub release as stable/latest and promotes Docker tags.

## Failure Handling

If a release fails in CI or in `dev/ops/prod`:

- Do not patch that failed release version.
- Do not force-tag or re-open the abandoned version.
- Continue with the next SemVer version in the next run.

Skipping versions is expected behavior.

## Local Script (workflow backend)

The workflows use `scripts/release-train.sh`.
You can run the same flow manually:

```bash
# Prepare branches (auto version)
./scripts/release-train.sh prepare --beyla-repo grafana/beyla

# Prepare branches (explicit version)
./scripts/release-train.sh prepare --version v4.3.0 --beyla-repo grafana/beyla

# Create tags and prereleases (after CI is green)
./scripts/release-train.sh tag --version v4.3.0 --beyla-repo grafana/beyla
```

## Checking if an OBI PR shipped in Beyla

Use:

```bash
./scripts/release-lookup.sh --obi <PR_OR_ISSUE_NUMBER>
```
