# Process of making a new Beyla release based on the upstream OBI distribution

## Introduction

Beyla's code was donated to OpenTelemetry and lives under the project [OpenTelemetry eBPF Instrumentation (OBI)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation).

This upstream code-base is still very much in active development and we still haven't met all
criteria to make an initial release of the upstream project. At the same time Grafana Beyla is
production supported product, which we offer to our users, therefore we'll need to continue making releases.

To ensure we have stable branches to make our Beyla releases, for the time being we have the following
repository configuration and release process.

## Beyla main branch

Beyla's main branch is always pinned to a specific hash of the upstream OpenTelemetry eBPF Instrumentation 
project. We use a git sub-module so we can build the eBPF binaries directly. Beyla's main branch closely
tracks OBI's main branch and the hash is moved forward from time to time.

## Beyla release branches

To have a stable OBI branch on which we base our Beyla releases, for now, we use [Grafana's fork of the OBI
project](https://github.com/grafana/opentelemetry-ebpf-instrumentation). This repository main branch
is synced directly from the OpenTelemetry upstream OBI repository, but it contains specific release branches
with point in time code.

Below we have the general outline of the steps required to make a new Beyla release branch.

### Step 1: Sync the Grafana OBI version with the upstream

Make a PR from upstream OBI to Grafana OBI and merge the changes. This ensures that we have
the latest upstream changes from OBI before we cut the release. If you want a specific hash
then checkout that hash and manually push to the Grafana OBI main branch.

### Step 2: Create new release branch in Grafana OBI

To start the process we first need to make a new release branch in [Grafana's fork of the OBI
project](https://github.com/grafana/opentelemetry-ebpf-instrumentation). 
After the branch is made, we preferably also make a tag and a release, which can follow any 
release numbering, e.g. v1.2.0.

If there are any OBI upstream changes that we consider perhaps too new and experimental to
be shipped to our end users, we can perform changes to the newly cut release branch and 
adjust the code. We can also change defaults in this release, if the Grafana desired defaults should
be different than the upstream OBI.

### Step 3: Create a new Beyla release branch of main

Just as usual create a new release branch off main in Beyla's repo and make sure you
follow the Beyla release naming schedule.

### Step 4: Point the release branch to the Grafana OBI release

The Beyla main repository sub-module points to the upstream OBI repository. We need 
to change that to make it point to the new Grafana OBI branch we cut.

Beyla's main sub-module definition (`.gitmodules`) will look like this:

```
[submodule "obi-src"]
	path = .obi-src
	url = https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation.git
```

Check-out the release branch you just cut and edit the `.gitmodules` file to point 
it to the Grafana OBI branch, e.g. for branch `release-1.2`.

```
[submodule "obi-src"]
	path = .obi-src
	url = https://github.com/grafana/opentelemetry-ebpf-instrumentation.git
	branch = release-1.2
```

Run, to refresh the submodules:

```
git submodule sync
```

This may pull in unexpected files, so check the Git repository branch
and remove any changes you have to other files than `.gitmodules` and `modules.txt`.

Next update the submodule:

```
git submodule update --checkout --remote
git add .
```

Commit your changes.

Run the following to update your local docker generate image

```
 make docker-generate
```

We want to ship all Beyla releases with binaries so it can be embedded in Alloy.
Edit your release branch `.gitignore` and remove the following exclusions:

```
*_bpfel.go
*_bpfel.o
pkg/internal/otelsdk/grafana-opentelemetry-java.jar
```

Vendor the Grafana OBI to build the binaries:

```
make vendor-obi
```

Commit all your file changes and make a PR to the release branch to ensure your changes run clear with the Beyla release CI.

### Step 5: Release the new Beyla version

Once all changes are made and tested, we can release the new Beyla version. This involves creating a new Git tag and pushing it to the Beyla repository. Checkout to the release branch and run the following commands:

```
git tag vX.Y.Z
git push origin vX.Y.Z
```

Once the tag is pushed, we can create a new release in the Beyla repository.

## Fixes to the release branches

If we have to fix something to the Grafana OBI or Beyla release branches
we do that just as usual. Make the PR first in the Grafana OBI release branch,
merge the code, make a PR with the updated Grafana OBI branch in Beyla, get approval,
pass CI and merge.

All fixes are to be forward-ported to the upstream OBI repository, don't put
fixes in the Grafana OBI main branch. If you want to update the Grafana OBI main 
branch with the fix, it must be first merged in upstream OBI and then you can sync
the changes to the Grafana OBI main.