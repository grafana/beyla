# Beyla Release

## Overview

Beyla embeds OBI as the `.obi-src` git submodule.
Beyla and `grafana/opentelemetry-ebpf-instrumentation` are versioned
independently.

The release process follows a weekly release train and Semantic Versioning only:

- Version format: `vMAJOR.MINOR.PATCH`
- No RC suffixes
- `MINOR` bumps for each weekly train slot
- `PATCH` bumps when multiple releases are needed in the same week
- `MAJOR` bumps only for breaking Go API changes
- Failed/abandoned versions are skipped (no retroactive patching)

Releases move through environments: `dev -> ops -> prod`.
A version starts as a prerelease and is promoted to stable/latest once validated
in `ops` (no unexpected errors or panics). The stable release is then deployed
to `prod`.

Example used in this document:

- Beyla release: `v3.0.0`
- OBI release: `v1.0.0`

## Automation Workflows

- `bot_sync-obi-fork.yml`: continuously syncs Grafana OBI fork main with upstream.
- `bot_sync-obi-submodule.yml`: weekly (Monday) update of Beyla `.obi-src` on `main`.
- [`release-train-prepare.yml`](../.github/workflows/release-train-prepare.yml): creates or updates OBI and Beyla release branches and regenerates artifacts.
  - Manual dispatch after OBI fork is synced.
  - Supports separate Beyla and OBI versions.
- [`release-train-tag.yml`](../.github/workflows/release-train-tag.yml): creates GitHub prereleases and SemVer tags in OBI and Beyla.
  - Manual dispatch after release branch CI is green.
  - Supports separate Beyla and OBI versions.
- [`promote-patch-to-stable.yml`](../.github/workflows/promote-patch-to-stable.yml): marks a prerelease as stable/latest and promotes Docker tags.

## End-to-End Flow

### 1. Preconditions

- OBI fork is synced from upstream.
- Beyla `main` is synced to latest intended OBI state.
- CI on Beyla `main` is green.
- Example below assumes Beyla `v3.0.0` and OBI `v1.0.0`.

### 2. Create release branches

Run [`release-train-prepare.yml`](https://github.com/grafana/beyla/actions/workflows/release-train-prepare.yml)
with separate Beyla and OBI versions, or do the same work manually.

Step outcome:

This creates `release-v1.0.0` in OBI and `release-v3.0.0` in Beyla. Both are
based on the OBI SHA pinned by Beyla `main`, and both get their release
artifacts committed before CI runs.

First, inspect Beyla `main` and confirm the OBI SHA that it pins. For example, 
Beyla `main` points to OBI commit `8634fc94ab21b86dd829fa92c87d8120790de337`.

```bash
cd /path/to/beyla
git fetch --prune origin
git checkout origin/main
git ls-tree origin/main .obi-src
```

Next, create the OBI release branch for `v1.0.0` from that pinned SHA and
generate the OBI artifacts that belong on the release branch.

```bash
cd /path/to/opentelemetry-ebpf-instrumentation
git fetch --prune origin
git checkout 8634fc94ab21b86dd829fa92c87d8120790de337
git checkout -B release-v1.0.0

make docker-generate
make java-build

git add -A
if ! git diff --cached --quiet; then
  git commit -m "Release v1.0.0 artifacts"
fi
git push -u origin release-v1.0.0
```

Then create the Beyla release branch for `v3.0.0`, keep `.obi-src` pinned to
the same OBI SHA, and generate the Beyla release artifacts.

```bash
cd /path/to/beyla
git fetch --prune origin
git checkout -B release-v3.0.0 origin/main

git submodule sync --recursive
git submodule update --init --recursive
git -C .obi-src fetch --prune origin
git -C .obi-src checkout 8634fc94ab21b86dd829fa92c87d8120790de337

git add .obi-src
git commit -m "Update obi submodule (v3.0.0)"

make vendor-obi
make java-build

git add -A
git commit -m "Release v3.0.0 artifacts"
git push -u origin release-v3.0.0
```

### 3. Wait for release branch CI

Ensure both release branches are green:

- `grafana/opentelemetry-ebpf-instrumentation:release-v1.0.0`
- `grafana/beyla:release-v3.0.0`

### 4. Create prereleases and tags

Run [`release-train-tag.yml`](https://github.com/grafana/beyla/actions/workflows/release-train-tag.yml)
with the Beyla and OBI versions, or do the same work manually after both
release branches are green.

Step outcome:

This creates the `v1.0.0` tag and prerelease in OBI and the `v3.0.0` tag and
prerelease in Beyla.

First, tag the OBI release branch and create the OBI prerelease.

```bash
cd /path/to/opentelemetry-ebpf-instrumentation
git fetch --prune --tags origin
git checkout -B release-v1.0.0 origin/release-v1.0.0

git tag v1.0.0 "$(git rev-parse HEAD)"
git push origin refs/tags/v1.0.0

gh release create v1.0.0 \
  --repo grafana/opentelemetry-ebpf-instrumentation \
  --target "$(git rev-parse HEAD)" \
  --title v1.0.0 \
  --prerelease \
  --notes "Release v1.0.0"
```

Then tag the Beyla release branch and create the Beyla prerelease.

```bash
cd /path/to/beyla
git fetch --prune --tags origin
git checkout -B release-v3.0.0 origin/release-v3.0.0

git tag v3.0.0 "$(git rev-parse HEAD)"
git push origin refs/tags/v3.0.0

gh release create v3.0.0 \
  --repo grafana/beyla \
  --target "$(git rev-parse HEAD)" \
  --title v3.0.0 \
  --prerelease \
  --notes "Release v3.0.0"
```

### 5. Promote to stable/latest

When the release has been deployed to `ops` and validated (no unexpected errors
or panics), promote to stable. Because `ops` closely resembles `prod`, validating
there is sufficient to declare a stable release — this reduces overall time to
stable compared to waiting for a full `prod` cycle.

Run [`promote-patch-to-stable.yml`](https://github.com/grafana/beyla/actions/workflows/promote-patch-to-stable.yml) with `version_tag=v3.0.0`.

Step outcome:

This marks the Beyla GitHub release as stable/latest and promotes the Docker
tags for that version.

```bash
gh workflow run promote-patch-to-stable.yml \
  --repo grafana/beyla \
  -f version_tag=v3.0.0
```

### 6. Post-promotion follow-up

After Beyla `v3.0.0` is promoted to stable/latest, complete the downstream
version bumps and deploy the stable release to `prod`.

#### Kubernetes Helm chart

Bump the Beyla Helm chart in this repository, as in
[#2661](https://github.com/grafana/beyla/pull/2661):

- Update `charts/beyla/Chart.yaml`:
  - Set `appVersion` to the promoted Beyla version.
  - Bump the chart `version`.
- Regenerate Helm chart docs with `make helm-docs`.
- Open and merge the Helm chart PR.
- Run the Beyla
  [helm-release.yml](https://github.com/grafana/beyla/actions/workflows/helm-release.yml)
  workflow after the Helm chart PR is merged.

#### Deploy to prod

Deploy the stable Beyla release to `prod` using the updated Helm chart.

#### Alloy

Use the Grafana Alloy workflow
[agent_bump_beyla.yml](https://github.com/grafana/alloy/actions/workflows/agent_bump_beyla.yml)
to prepare the Beyla bump:

- A draft PR can be prepared as soon as the Beyla release is available.
- If the new Beyla version requires OpenTelemetry dependency updates in Alloy,
  coordinate with the Alloy team and wait for those changes before merging.
- The workflow attempts to upgrade the component to the latest release, but
  manual follow-up may still be needed if the Beyla release contains larger
  architectural changes.
- Merge the Alloy PR only after the Beyla release has been promoted to
  stable/latest.
## Failure Handling

If a release fails in CI or in `dev/ops/prod`:

- Do not patch that failed release version.
- Do not force-tag or re-open the abandoned version.
- Continue with the next SemVer version in the next run.

Skipping versions is expected behavior.

## Manual CLI Notes

The workflows above use `scripts/release-train.sh` under the hood, but the
commands shown in each step are the manual `git`/`make`/`gh` equivalents.
Use the manual path when Beyla and OBI are intentionally released with
different version numbers, or when you want to inspect each step directly.

## Checking if an OBI PR shipped in Beyla

Use [scripts/release-lookup.sh](../scripts/release-lookup.sh) to check whether an
OBI PR or issue shipped in Beyla:

```bash
./scripts/release-lookup.sh --obi <PR_OR_ISSUE_NUMBER>
```

Example below to find if the OBI PR linked to this issue
https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/995
was released in Beyla (it wasn't):

```shell
./scripts/release-lookup.sh --obi 995
[info] Issue #995: Use HTTP Host header for service name resolution when K8s lookup fails (state: closed)
[info] Found linked PR #997: fix: fallback to http host header for service graph

OBI Issue #995 (PR #997) was not yet released as part of Beyla
```

Another example with
https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/896:

```shell
./scripts/release-lookup.sh --obi 896

OBI PR #896 was released as part of Beyla 2.8.0
```
