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

# The Beyla-only OATS adaptation must change only the generic Kafka input
# retry window, leave the upstream fixture untouched, and reject source drift.
mkdir -p "$tmp/oats-window"
cat >"$tmp/oats-window/upstream.yaml" <<'YAML'
input:
  - path: /produce
    retry:
      timeout: 10s
      interval: 500ms
      continue_after_success: true
expected:
  traces:
    - traceql: kafka
      match_spans:
        - name: send my-topic
          match_type: strict
    - traceql: http
      match_spans:
        - name: GET /produce
          match_type: strict
YAML
cp "$tmp/oats-window/upstream.yaml" "$tmp/oats-window/beyla.yaml"
"$root/scripts/extend-beyla-kafka-oats-window.sh" "$tmp/oats-window/beyla.yaml"
sed '/^input:[[:space:]]*$/,/^expected:[[:space:]]*$/s/^      timeout: 10s$/      timeout: 30s/' \
  "$tmp/oats-window/upstream.yaml" >"$tmp/oats-window/expected.yaml"
diff -u "$tmp/oats-window/expected.yaml" "$tmp/oats-window/beyla.yaml"
[[ $(grep -F -c '      timeout: 10s' "$tmp/oats-window/upstream.yaml") -eq 1 ]]
for invalid_value in 'wrong-duration' 'trailing-comment' 'shifted-indentation'; do
  cp "$tmp/oats-window/upstream.yaml" "$tmp/oats-window/beyla.yaml"
  case "$invalid_value" in
  wrong-duration)
    sed 's/timeout: 10s$/timeout: 5s/' "$tmp/oats-window/beyla.yaml" >"$tmp/oats-window/invalid.yaml"
    ;;
  trailing-comment)
    sed 's/timeout: 10s$/timeout: 10s # note/' "$tmp/oats-window/beyla.yaml" >"$tmp/oats-window/invalid.yaml"
    ;;
  shifted-indentation)
    sed 's/^      timeout: 10s$/        timeout: 10s/' "$tmp/oats-window/beyla.yaml" >"$tmp/oats-window/invalid.yaml"
    ;;
  esac
  mv "$tmp/oats-window/invalid.yaml" "$tmp/oats-window/beyla.yaml"
  cp "$tmp/oats-window/beyla.yaml" "$tmp/oats-window/unchanged.yaml"
  if "$root/scripts/extend-beyla-kafka-oats-window.sh" "$tmp/oats-window/beyla.yaml"; then
    echo 'Kafka OATS input-window adaptation must reject unexpected source values.' >&2
    exit 1
  fi
  diff -u "$tmp/oats-window/unchanged.yaml" "$tmp/oats-window/beyla.yaml"
done

echo 'mise task contract tests passed'
