# Shared Mise setup action

Pass a named `profile` to select the exact configured tools a job may use. The
canonical profiles and their tool sets live in [`resolve-profile.sh`](resolve-profile.sh);
for example, `profile: integration` enables the Go, BPF, Clang/LLVM, Kind, and
gotestsum tools needed by integration jobs. Use `profile: none` when no Mise
tools are needed. The action installs only the selected tools.

Go module and Go build caches are separate optional caches controlled by the
`cache-modules` and `cache-build` inputs. Both are disabled by default and do
not affect which Mise tools the profile enables.
