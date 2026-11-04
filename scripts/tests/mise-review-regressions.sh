#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
make_bin=$(command -v make)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

# This script runs before setup-mise in CI. Reinvoke it with a hostile Mise
# shim first on PATH and assert that no direct Mise call escapes into it.
if [[ "${MISE_REVIEW_HERMETIC_CHILD:-}" != 1 ]]; then
  mkdir -p "$tmp/hostile-bin"
  cat > "$tmp/hostile-bin/mise" <<'SH'
#!/usr/bin/env bash
touch "$MISE_REVIEW_MISE_SENTINEL"
exit 97
SH
  chmod +x "$tmp/hostile-bin/mise"
  MISE_REVIEW_HERMETIC_CHILD=1 MISE_REVIEW_MISE_SENTINEL="$tmp/mise-was-called" \
    PATH="$tmp/hostile-bin:$PATH" bash "$0" >"$tmp/hermetic-output"
  [[ ! -e "$tmp/mise-was-called" ]]
fi

cat > "$tmp/bin/mise" <<'SH'
#!/usr/bin/env bash
printf 'start %s CMD=%s GOOS=%s\n' "$*" "${CMD-unset}" "${GOOS-unset}" >> "$EVENTS"
sleep 0.1
echo "end $*" >> "$EVENTS"
SH
cat > "$tmp/bin/go" <<'SH'
#!/usr/bin/env bash
printf 'args=%s GOOS=%s GOARCH=%s\n' "$*" "${GOOS-unset}" "${GOARCH-unset}" >> "$GO_LOG"
SH
cat > "$tmp/bin/kind" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$KIND_LOG"
SH
cat > "$tmp/bin/docker" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "$tmp/bin/"*

# Each requested Make goal is forwarded separately and runs serially by default.
env -u GOOS -u GOARCH -u MAKEFLAGS -u MFLAGS -u MAKEOVERRIDES EVENTS="$tmp/events" \
  PATH="$tmp/bin:$PATH" make -C "$root" alpha beta CMD=custom >/dev/null
[[ $(cat "$tmp/events") == $'start run alpha CMD=custom GOOS=unset\nend run alpha\nstart run beta CMD=custom GOOS=unset\nend run beta' ]]

# Default target is all, command-line variables are exported, and -n is safe.
rm -f "$tmp/events"
env -u GOOS -u GOARCH -u MAKEFLAGS -u MFLAGS -u MAKEOVERRIDES EVENTS="$tmp/events" \
  PATH="$tmp/bin:$PATH" make -C "$root" CMD=default >/dev/null
grep -q '^start run all CMD=default ' "$tmp/events"
rm -f "$tmp/events"
env -u GOOS -u GOARCH -u MAKEFLAGS -u MFLAGS -u MAKEOVERRIDES EVENTS="$tmp/events" \
  PATH="$tmp/bin:$PATH" make -C "$root" -n alpha CMD=dry >"$tmp/dryrun"
[[ ! -e "$tmp/events" ]]
grep -q 'mise run alpha' "$tmp/dryrun"

# Dry-run VM and mixed goals print only; neither fake Go nor Mise executes.
env -u GOOS -u GOARCH -u MAKEFLAGS -u MFLAGS -u MAKEOVERRIDES EVENTS="$tmp/events" \
  GO_LOG="$tmp/go" PATH="$tmp/bin:$PATH" make -C "$root" -n run-integration-test-vm alpha \
  >"$tmp/vm-dryrun"
grep -q 'bash .mise/tasks/integration/run/vm' "$tmp/vm-dryrun"
grep -q 'mise run alpha' "$tmp/vm-dryrun"
[[ ! -e "$tmp/events" && ! -e "$tmp/go" ]]

# VM execution works with an isolated PATH containing bash and Go, but no Mise.
if [[ -e /precompiled-tests/integration.test ]]; then
  echo 'Cannot run VM regression while /precompiled-tests/integration.test exists' >&2
  exit 1
fi
mkdir -p "$tmp/vm-bin"
ln -s "$(command -v bash)" "$tmp/vm-bin/bash"
cat > "$tmp/vm-bin/go" <<EOF
#!$tmp/vm-bin/bash
printf '%s\\n' "\$*" >> "$tmp/vm-go"
EOF
chmod +x "$tmp/vm-bin/go"
if PATH="$tmp/vm-bin" command -v mise >/dev/null 2>&1; then
  echo 'Unexpected Mise found in isolated VM PATH' >&2
  exit 1
fi
PATH="$tmp/vm-bin" "$make_bin" -C "$root" run-integration-test-vm TEST_PATTERN=VMProbe >/dev/null
grep -q VMProbe "$tmp/vm-go"

# The managed kind binary is resolved through PATH; an explicit KIND override
# still wins. Mocks ensure cleanup invokes no real containers or images.
env -u KIND PATH="$tmp/bin:$PATH" KIND_LOG="$tmp/kind" OCI_BIN="$tmp/bin/docker" \
  COMPOSE_ARGS='' bash "$root/.mise/tasks/clean/integration-test" >/dev/null
grep -q 'delete cluster' "$tmp/kind"
cp "$tmp/bin/kind" "$tmp/custom-kind"
KIND_LOG="$tmp/kind-override" KIND="$tmp/custom-kind" \
  OCI_BIN="$tmp/bin/docker" COMPOSE_ARGS='' bash "$root/.mise/tasks/clean/integration-test" >/dev/null
grep -q 'delete cluster' "$tmp/kind-override"

# Exercise the real OATS debug task script with a mock executable. A temporary
# generated-suite tree keeps this check independent of OBI generation. It
# resolves Mise-managed Ginkgo from PATH by default; explicit OATS_GINKGO and
# legacy GINKGO command overrides remain supported.
cat > "$tmp/bin/ginkgo" <<'SH'
#!/usr/bin/env bash
printf '%s|%s|%s|%s|%s|%s\n' "$0" "$*" "$PWD" "${TESTCASE_BASE_PATH-unset}" \
  "${TESTCASE_MANUAL_DEBUG-unset}" "${TESTCASE_TIMEOUT-unset}" >> "$GINKGO_LOG"
SH
chmod +x "$tmp/bin/ginkgo"
oats_debug_script="$root/internal/test/oats/.mise/tasks/debug"
mkdir -p "$tmp/oats-root/internal/testgenerated/oats/kafka" \
  "$tmp/oats-root/internal/testgenerated/oats/ai"
MISE_MONOREPO_ROOT="$tmp/oats-root" GINKGO_LOG="$tmp/ginkgo-default" PATH="$tmp/bin:$PATH" \
  bash "$oats_debug_script"
grep -Fq "$tmp/bin/ginkgo|-v -r|$tmp/oats-root/internal/testgenerated/oats/kafka|./yaml|true|1h" "$tmp/ginkgo-default"
cp "$tmp/bin/ginkgo" "$tmp/custom-ginkgo"
MISE_MONOREPO_ROOT="$tmp/oats-root" GINKGO_LOG="$tmp/ginkgo-oats-override" \
  OATS_GINKGO="$tmp/custom-ginkgo" PATH="$tmp/bin:$PATH" \
  usage_suite=ai bash "$oats_debug_script"
grep -Fq "$tmp/custom-ginkgo|-v -r|$tmp/oats-root/internal/testgenerated/oats/ai|./yaml|true|1h" "$tmp/ginkgo-oats-override"
MISE_MONOREPO_ROOT="$tmp/oats-root" GINKGO_LOG="$tmp/ginkgo-override" \
  GINKGO="$tmp/custom-ginkgo" PATH="$tmp/bin:$PATH" \
  bash "$oats_debug_script"
grep -Fq "$tmp/custom-ginkgo|-v -r|$tmp/oats-root/internal/testgenerated/oats/kafka|./yaml|true|1h" "$tmp/ginkgo-override"
if MISE_MONOREPO_ROOT="$tmp/oats-root" GINKGO_LOG="$tmp/ginkgo-invalid" \
  PATH="$tmp/bin:$PATH" usage_suite=../../outside bash "$oats_debug_script" >/dev/null 2>&1; then
  echo 'OATS debug task accepted a suite path outside its allowlist' >&2
  exit 1
fi
[[ ! -e "$tmp/ginkgo-invalid" ]]

# Git metadata failures are nonfatal for all metadata-enabled compile tasks.
cat > "$tmp/bin/git" <<'SH'
#!/usr/bin/env bash
exit 1
SH
chmod +x "$tmp/bin/git"
for task in _default cache debug coverage; do
  log="$tmp/go-$task"
  case "$task" in
    cache) env_args=(CACHE_CMD=k8s-cache) ;;
    *) env_args=(CMD=beyla) ;;
  esac
  env -u RELEASE_VERSION -u RELEASE_REVISION GO_LOG="$log" PATH="$tmp/bin:$PATH" \
    MISE_CONFIG_ROOT="$root" "${env_args[@]}" bash "$root/.mise/tasks/compile/$task" \
    >"$tmp/$task-out" 2>"$tmp/$task-err"
  [[ ! -s "$tmp/$task-err" ]]
  [[ -s "$log" ]]
done

# Valid release overrides bypass Git, and explicitly empty build-only values
# remain empty rather than silently falling back to defaults.
GO_LOG="$tmp/go-overrides" PATH="$tmp/bin:$PATH" MISE_CONFIG_ROOT="$root" CMD='' \
  GOOS='' GOARCH='' RELEASE_VERSION=review-override RELEASE_REVISION=abc123 \
  bash "$root/.mise/tasks/compile/_default" >"$tmp/override-out" 2>"$tmp/override-err"
[[ ! -s "$tmp/override-err" ]]
grep -q 'review-override' "$tmp/go-overrides"
grep -q 'abc123' "$tmp/go-overrides"
grep -q 'GOOS= GOARCH=' "$tmp/go-overrides"
grep -q -- '-o bin/' "$tmp/go-overrides"

# Integration coverage obeys the configured exclusion expression.
mkdir -p "$tmp/test-output"
cat > "$tmp/bin/go" <<'SH'
#!/usr/bin/env bash
if [[ "$*" == *'covdata textfmt'* ]]; then
  while (($#)); do
    if [[ $1 == -o ]]; then shift; printf 'mode: set\ncustom.go:1.1,2.1 1 1\nkeep.go:1.1,2.1 1 1\n' > "$1"; fi
    shift || true
  done
fi
SH
chmod +x "$tmp/bin/go"
PATH="$tmp/bin:$PATH" TEST_OUTPUT="$tmp/test-output" EXCLUDE_COVERAGE_FILES=custom.go \
  bash "$root/.mise/tasks/integration/coverage-data" >/dev/null
! grep -q custom.go "$tmp/test-output/itest-covdata.txt"
grep -q keep.go "$tmp/test-output/itest-covdata.txt"

# The workflow passes the shard ID as a task argument, and the task reads the
# matching profile (not a profile selected by another similarly named step).
coverage_step=$(sed -n '/- name: Exclude generated files from coverage/,/- id: get-codecov-token/p' \
  "$root/.github/workflows/pull_request.yml")
grep -q -- '--shard-id "${SHARD_ID}"' <<<"$coverage_step"
mkdir -p "$tmp/shard-output"
printf 'mode: set\nkeep-3.go:1.1,2.1 1 1\n' > "$tmp/shard-output/cover-shard-3.all.txt"
printf 'mode: set\nwrong-shard.go:1.1,2.1 1 1\n' > "$tmp/shard-output/cover-shard-2.all.txt"
PATH="$tmp/bin:$PATH" TEST_OUTPUT="$tmp/shard-output" SHARD_ID=3 EXCLUDE_COVERAGE_FILES=never-match \
  bash "$root/.mise/tasks/coverage/exclude-generated-shard"
grep -q keep-3.go "$tmp/shard-output/cover-shard-3.txt"
[[ ! -e "$tmp/shard-output/cover-shard-2.txt" ]]

# Unit-shard package strings are split only on whitespace and passed as array
# elements, so glob characters remain literal and multiline matrix values work.
cat > "$tmp/bin/setup-envtest" <<'SH'
#!/usr/bin/env bash
echo /fake/envtest
SH
cat > "$tmp/bin/gotestsum" <<'SH'
#!/usr/bin/env bash
printf '<%s>\n' "$@" > "$GOTESTSUM_LOG"
SH
chmod +x "$tmp/bin/setup-envtest" "$tmp/bin/gotestsum"
mkdir -p "$tmp/unit-output"
GOTESTSUM_LOG="$tmp/gotestsum" PATH="$tmp/bin:$PATH" TEST_OUTPUT="$tmp/unit-output" \
  ENVTEST_K8S_VERSION=1.30.0 SHARD_ID=3 \
  UNIT_TEST_PACKAGES=$'./pkg/alpha\n./pkg/beta ./literal*' \
  bash "$root/.mise/tasks/test/shard" >/dev/null
grep -Fx '<./pkg/alpha>' "$tmp/gotestsum"
grep -Fx '<./pkg/beta>' "$tmp/gotestsum"
grep -Fx '<./literal*>' "$tmp/gotestsum"

echo 'mise review regressions passed'
