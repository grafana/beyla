# Shared Mise setup action

Pass a named `profile` to select the exact configured tools a job may use. The
canonical profiles and their tool sets live in [`resolve-profile.sh`](resolve-profile.sh);
for example, `profile: integration` enables the Go, BPF, Clang/LLVM, Kind, and
gotestsum tools needed by integration jobs. Use `profile: none` when no Mise
tools are needed. The action installs only the selected tools.

By default, the action restores a shared `downloads-cas` cache keyed by runner
OS/architecture, the root `mise.lock`, and the setup action (which owns the
pinned Mise runtime and cache recipe). The root lock is authoritative for the
monorepo tools, so unrelated submodule lockfiles are not part of the key.
Only the trusted default-branch workflow
[`mise-download-cache.yml`](../../workflows/mise-download-cache.yml) writes the
union cache. Pull requests with an unchanged lock can restore it; a PR that
changes the lock is cold until its changes merge and the default-branch warmer
runs. Set `cache-downloads: "false"` for a job that should not restore the
shared cache (for example, jobs that use no Mise tools).

The shared cache contains verified downloaded archives only—not Mise install
directories or compiled tool outputs. Mise still extracts and installs the
job's selected tools; tools built from source still compile, and Go module and
build caches remain separate. Because the union may include downloads a
particular profile does not use, restores can transfer extra bytes. The trusted
producer disables local LRU pruning to avoid publishing an incomplete snapshot,
but publishes no cache larger than 2 GiB per platform. If it exceeds that bound,
it records the measured size and skips the save; consumers then download from
the original sources.
