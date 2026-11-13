#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat >"$tmp/bin/go" <<'SH'
#!/usr/bin/env bash
printf 'args=%s GOOS=%s GOARCH=%s\n' "$*" "${GOOS-unset}" "${GOARCH-unset}" >> "$GO_LOG"
SH
cat >"$tmp/bin/kind" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$KIND_LOG"
SH
cat >"$tmp/bin/docker" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "$tmp/bin/"*

# These pre-bootstrap contract tests must not invoke Mise, even if it is on PATH.
if [[ "${MISE_CONTRACT_HERMETIC_CHILD:-}" != 1 ]]; then
  mkdir -p "$tmp/hostile-bin"
  cat >"$tmp/hostile-bin/mise" <<'SH'
#!/usr/bin/env bash
touch "$MISE_CONTRACT_MISE_SENTINEL"
exit 97
SH
  chmod +x "$tmp/hostile-bin/mise"
  MISE_CONTRACT_HERMETIC_CHILD=1 MISE_CONTRACT_MISE_SENTINEL="$tmp/mise-was-called" \
    PATH="$tmp/hostile-bin:$PATH" bash "${BASH_SOURCE[0]}" >"$tmp/hermetic-output"
  [[ ! -e "$tmp/mise-was-called" ]]
fi

# The integration matrix keeps multiple test paths as separate arguments,
# including when a filename contains spaces.
matrix_dir="$tmp/matrix inputs"
mkdir -p "$matrix_dir"
cat >"$matrix_dir/first file_test.go" <<'GO'
//go:build integration

package test

func TestAlpha() {}
GO
cat >"$matrix_dir/second_test.go" <<'GO'
//go:build integration

package test

func TestBeta() {}
GO
printf '{}\n' >"$tmp/matrix-weights.json"
matrix_output=$(WEIGHTS_FILE="$tmp/matrix-weights.json" \
  bash "$root/scripts/generate-integration-matrix.sh" "" "$matrix_dir" 2 Test 2>&1)
grep -q "Total tests matching 'Test': 2" <<<"$matrix_output"
grep -q 'TestAlpha' <<<"$matrix_output"
grep -q 'TestBeta' <<<"$matrix_output"

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
cat >"$tmp/bin/ginkgo" <<'SH'
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

# Integration coverage obeys the configured exclusion expression.
mkdir -p "$tmp/test-output"
cat >"$tmp/bin/go" <<'SH'
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
grep -q custom.go "$tmp/test-output/itest-covdata.txt" && exit 1
grep -q keep.go "$tmp/test-output/itest-covdata.txt"

# The workflow passes the shard ID as a task argument, and the task reads the
# matching profile (not a profile selected by another similarly named step).
coverage_step=$(sed -n '/- name: Exclude generated files from coverage/,/- id: get-codecov-token/p' \
  "$root/.github/workflows/pull_request.yml")
grep -q -- "--shard-id \"\${SHARD_ID}\"" <<<"$coverage_step"
mkdir -p "$tmp/shard-output"
printf 'mode: set\nkeep-3.go:1.1,2.1 1 1\n' >"$tmp/shard-output/cover-shard-3.all.txt"
printf 'mode: set\nwrong-shard.go:1.1,2.1 1 1\n' >"$tmp/shard-output/cover-shard-2.all.txt"
PATH="$tmp/bin:$PATH" TEST_OUTPUT="$tmp/shard-output" SHARD_ID=3 EXCLUDE_COVERAGE_FILES=never-match \
  bash "$root/.mise/tasks/coverage/exclude-generated-shard"
grep -q keep-3.go "$tmp/shard-output/cover-shard-3.txt"
[[ ! -e "$tmp/shard-output/cover-shard-2.txt" ]]

# Unit-shard package strings are split only on whitespace and passed as array
# elements, so glob characters remain literal and multiline matrix values work.
cat >"$tmp/bin/setup-envtest" <<'SH'
#!/usr/bin/env bash
echo /fake/envtest
SH
cat >"$tmp/bin/gotestsum" <<'SH'
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

# Contract-test the shared pull-request integration shard task without Mise or
# real test execution. These cases cover the three workflow configurations.
cat >"$tmp/bin/gotestsum" <<'SH'
#!/usr/bin/env bash
printf 'called\n' >> "$GOTESTSUM_CALLS"
printf '%s\n' "$@" > "$GOTESTSUM_LOG"
exit "${GOTESTSUM_EXIT:-0}"
SH
chmod +x "$tmp/bin/gotestsum"
shard_task="$root/.mise/tasks/integration/run/shard"
shard_env=(
  "PATH=$tmp/bin:$PATH"
  "MATRIX_ID=shard-4"
  'MATRIX_JSON={"id":"shard-4","test_pattern":"TestAlpha"}'
  'MATRIX_TEST_PATTERN=TestAlpha|TestBeta'
  "RUN_NUMBER=99"
  "TEST_TAGS=integration"
  "REPORT_DIR=$tmp/reports"
  "GOTESTSUM_LOG=$tmp/shard-gotestsum"
  "GOTESTSUM_CALLS=$tmp/shard-calls"
)
gotestsum_prefix=(
  --rerun-fails=2 --rerun-fails-max-failures=2 --rerun-fails-abort-on-data-race
)
gotestsum_suffix=(
  -ftestname "--jsonfile=$tmp/reports/test-run-99-shard-4.log" --
  -count=1 -tags=integration -timeout 30m -mod vendor
)
check_args() {
  printf '%s\n' "$@" >"$tmp/expected-gotestsum"
  diff -u "$tmp/expected-gotestsum" "$tmp/shard-gotestsum"
}

env "${shard_env[@]}" bash "$shard_task" ./internal/testgenerated/integration -race \
  '-run=^(TestAlpha|TestBeta)$' >"$tmp/integration-shard-output"
check_args "${gotestsum_prefix[@]}" --packages=./internal/testgenerated/integration \
  "${gotestsum_suffix[@]}" -race '-run=^(TestAlpha|TestBeta)$' ./internal/testgenerated/integration
grep -Fxq 'Partition' "$tmp/integration-shard-output"
grep -Fxq '{"id":"shard-4","test_pattern":"TestAlpha"}' "$tmp/integration-shard-output"
[[ -d "$tmp/reports" ]]

env "${shard_env[@]}" bash "$shard_task" ./internal/testgenerated/integration \
  '-run=^(TestAlpha|TestBeta)$' >/dev/null
check_args "${gotestsum_prefix[@]}" --packages=./internal/testgenerated/integration \
  "${gotestsum_suffix[@]}" '-run=^(TestAlpha|TestBeta)$' ./internal/testgenerated/integration

env "${shard_env[@]}" MATRIX_TEST_PATTERN='./internal/testgenerated/integration/k8s/TestAlpha' \
  bash "$shard_task" './internal/testgenerated/integration/k8s/TestAlpha' -race >/dev/null
check_args "${gotestsum_prefix[@]}" \
  --packages=./internal/testgenerated/integration/k8s/TestAlpha "${gotestsum_suffix[@]}" \
  -race ./internal/testgenerated/integration/k8s/TestAlpha
[[ $(wc -l <"$tmp/shard-calls") -eq 3 ]]

invalid_calls="$tmp/invalid-shard-calls"
if env "${shard_env[@]}" MATRIX_TEST_PATTERN='' GOTESTSUM_CALLS="$invalid_calls" \
  bash "$shard_task" ./internal/testgenerated/integration >/dev/null 2>&1; then
  echo 'Integration shard accepted an empty pattern' >&2
  exit 1
fi
if env "${shard_env[@]}" GOTESTSUM_CALLS="$invalid_calls" bash "$shard_task" >/dev/null 2>&1; then
  echo 'Integration shard accepted a missing package' >&2
  exit 1
fi
[[ ! -e "$invalid_calls" ]]

if env "${shard_env[@]}" GOTESTSUM_EXIT=23 bash "$shard_task" \
  ./internal/testgenerated/integration >/dev/null 2>&1; then
  echo 'Integration shard did not propagate gotestsum failure' >&2
  exit 1
else
  shard_status=$?
fi
[[ "$shard_status" -eq 23 ]]

echo 'mise task contract tests passed'
