#!/usr/bin/env bash
set -Eeuo pipefail
report_error() {
  local status=$?
  printf 'mise task naming failed at line %s: %s (exit %s)\n' \
    "$LINENO" "$BASH_COMMAND" "$status" >&2
  exit "$status"
}
trap report_error ERR

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mise_bin=${MISE_BIN:-$(command -v mise || true)}
if [[ -z "$mise_bin" || ! -x "$mise_bin" ]]; then
  echo 'mise-task-naming requires an installed mise binary (set MISE_BIN)' >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# This regression is normally run with the configured mise runtime. Set
# MISE_EXPECTED_VERSION explicitly when auditing a particular compatibility
# floor/runtime version.
version=$("$mise_bin" --version)
if [[ -n "${MISE_EXPECTED_VERSION:-}" && "$version" != "$MISE_EXPECTED_VERSION"* ]]; then
  echo "expected mise $MISE_EXPECTED_VERSION, got: $version" >&2
  exit 1
fi
unset MISE_EXPECTED_VERSION
# Keep dry-run output stable for the task-plan parser even when CI forces ANSI.
export NO_COLOR=1
echo "checking task naming with $version"

# Generated OATS Go modules follow the single pinned Ginkgo version in Mise.
ginkgo_version=$(awk -F '"' '$1 ~ /^[[:space:]]*ginkgo = / { print $2; exit }' "$root/mise.toml")
grep -q "ginkgo_version=\$(awk -F" "$root/scripts/generate-obi-tests.sh"
configured_ginkgo_version=$(env -u MISE_ENABLE_TOOLS "$mise_bin" -C "$root" current ginkgo)
[[ "$ginkgo_version" == "$configured_ginkgo_version" ]]

# Every historical spelling should resolve to the same dry-run plan as its new
# task identity. Nothing is actually run and --skip-tools avoids tool installs.
check_task() {
  local old_name=$1 expected=$2 actual expected_output actual_raw expected_raw actual_status expected_status
  # Composite tasks need not print their own task ID (only their dependencies),
  # so compare the execution plan with the explicit canonical task identity.
  if actual_raw=$("$mise_bin" -C "$root" run --dry-run --skip-tools "$old_name" 2>&1); then
    actual_status=0
  else
    actual_status=$?
  fi
  if expected_raw=$("$mise_bin" -C "$root" run --dry-run --skip-tools "$expected" 2>&1); then
    expected_status=0
  else
    expected_status=$?
  fi
  actual=$(grep -F '] $ ' <<<"$actual_raw" || true)
  expected_output=$(grep -F '] $ ' <<<"$expected_raw" || true)
  if [[ "$actual_status" != 0 || "$expected_status" != 0 || -z "$actual" || "$actual" != "$expected_output" ]]; then
    printf 'legacy task %q did not resolve to %q; exit=%s raw output:\n%s\nexpected task exit=%s raw output:\n%s\n' \
      "$old_name" "$expected" "$actual_status" "$actual_raw" "$expected_status" "$expected_raw" >&2
    exit 1
  fi
}

check_task java-build //internal/java:build
check_task java-clean //internal/java:clean
check_task java-docker-build //internal/java:docker-build
check_task java-spotless-apply //internal/java:spotless-apply
check_task java-spotless-check //internal/java:spotless-check
check_task java-test //internal/java:test
check_task java-verify //internal/java:verify
check_task oats-prereq //internal/test/oats:prepare
check_task oats-integration-test-matrix-json //internal/test/oats:matrix
check_task oats-test //internal/test/oats:test
check_task oats-test-ai //internal/test/oats:test:ai
check_task oats-test-amqp //internal/test/oats:test:amqp
check_task oats-test-debug //internal/test/oats:debug
check_task oats-test-harness //internal/test/oats:test:harness
check_task oats-test-http //internal/test/oats:test:http
check_task oats-test-kafka //internal/test/oats:test:kafka
check_task oats-test-memcached //internal/test/oats:test:memcached
check_task oats-test-mongo //internal/test/oats:test:mongo
check_task oats-test-nats //internal/test/oats:test:nats
check_task oats-test-redis //internal/test/oats:test:redis
check_task oats-test-sql //internal/test/oats:test:sql

# Both the former root bare aliases and the old explicit root canonical names
# remain valid after those tasks move into named subprojects.
check_task java:build //internal/java:build
check_task java:clean //internal/java:clean
check_task java:docker-build //internal/java:docker-build
check_task java:spotless-apply //internal/java:spotless-apply
check_task java:spotless-check //internal/java:spotless-check
check_task java:test //internal/java:test
check_task java:verify //internal/java:verify
check_task oats:prereq //internal/test/oats:prepare
check_task oats:matrix:integration-test-json //internal/test/oats:matrix
check_task oats:test //internal/test/oats:test
check_task oats:test:ai //internal/test/oats:test:ai
check_task oats:test:amqp //internal/test/oats:test:amqp
check_task oats:test:debug //internal/test/oats:debug
check_task oats:test:harness //internal/test/oats:test:harness
check_task oats:test:http //internal/test/oats:test:http
check_task oats:test:kafka //internal/test/oats:test:kafka
check_task oats:test:memcached //internal/test/oats:test:memcached
check_task oats:test:mongo //internal/test/oats:test:mongo
check_task oats:test:nats //internal/test/oats:test:nats
check_task oats:test:redis //internal/test/oats:test:redis
check_task oats:test:sql //internal/test/oats:test:sql

# Existing callers may have qualified child tasks via their old project path,
# not only through root-level aliases. Keep those namespace-qualified names
# routable too.
check_task //oats:prereq //internal/test/oats:prepare
check_task //oats:matrix:integration-test-json //internal/test/oats:matrix
check_task //oats:test //internal/test/oats:test
check_task //oats:test:ai //internal/test/oats:test:ai
check_task //oats:test:amqp //internal/test/oats:test:amqp
check_task //oats:test:debug //internal/test/oats:debug
check_task //oats:test:harness //internal/test/oats:test:harness
check_task //oats:test:http //internal/test/oats:test:http
check_task //oats:test:kafka //internal/test/oats:test:kafka
check_task //oats:test:memcached //internal/test/oats:test:memcached
check_task //oats:test:mongo //internal/test/oats:test:mongo
check_task //oats:test:nats //internal/test/oats:test:nats
check_task //oats:test:redis //internal/test/oats:test:redis
check_task //oats:test:sql //internal/test/oats:test:sql

check_task matrix:unit-test-json //:test:matrix
check_task unit-test-matrix-json //:test:matrix
check_task integration:matrix:test-json //:integration:matrix
check_task integration-test-matrix-json //:integration:matrix
check_task integration:matrix:k8s-json //:integration:matrix:k8s
check_task k8s-integration-test-matrix-json //:integration:matrix:k8s
check_task integration:matrix:beyla-json //:integration:matrix:beyla
check_task beyla-integration-test-matrix-json //:integration:matrix:beyla
check_task integration:matrix:vm-json //:integration:matrix:multiprocess
check_task vm-integration-test-matrix-json //:integration:matrix:multiprocess
check_task integration:run:arm //:integration:run:multiprocess
check_task run-integration-test-arm //:integration:run:multiprocess
check_task integration:test:arm //:integration:test:multiprocess
check_task integration-test-arm //:integration:test:multiprocess
check_task compile:for-coverage //:compile:coverage
check_task compile-for-coverage //:compile:coverage
check_task compile:cache-for-coverage //:compile:cache-coverage
check_task compile-cache-for-coverage //:compile:cache-coverage
check_task docker:generate //:generate:docker
check_task docker-generate //:generate:docker
check_task generate-config-schema //:generate:config-schema
check_task generate-obi-tests //:generate:obi-tests
check_task test:unit-shard //:test:shard
check_task run-unit-test-shard //:test:shard

# No moved task should be duplicated as a public root wrapper. --all is needed
# to see monorepo children, but task identity still distinguishes root from the
# named child config.
"$mise_bin" -C "$root" tasks ls --all --json >"$tmp/tasks.json"
python3 - "$tmp/tasks.json" <<'PY'
import json, sys
tasks = json.load(open(sys.argv[1]))
names = [task.get("name", "") for task in tasks]
for moved in ("java:build", "java:clean", "java:docker-build", "java:spotless-apply",
              "java:spotless-check", "java:test", "java:verify", "oats:prereq",
              "oats:matrix:integration-test-json", "oats:test", "oats:test:ai",
              "oats:test:amqp", "oats:test:debug", "oats:test:harness",
              "oats:test:http", "oats:test:kafka", "oats:test:memcached",
              "oats:test:mongo", "oats:test:nats", "oats:test:redis", "oats:test:sql"):
    roots = [name for name in names if name == f"//:{moved}"]
    if roots:
        raise SystemExit(f"unexpected root wrapper task(s) for {moved}: {roots}")
PY

# The plans must point at the actual file-task implementations, not merely an
# alias entry that resolves without doing anything.
"$mise_bin" -C "$root" run --dry-run --skip-tools java-build >"$tmp/java-build-plan" 2>&1
grep -Fq '.mise/tasks/build' "$tmp/java-build-plan"
"$mise_bin" -C "$root" run --dry-run --skip-tools oats-test-debug >"$tmp/oats-debug-plan" 2>&1
grep -Fq 'internal/test/oats/.mise/tasks/debug' "$tmp/oats-debug-plan"

# The configured mise parses task input flags. This runs after setup-mise in CI.
"$mise_bin" -C "$root" run test:unit-shard --help >"$tmp/unit-shard-help"
grep -q -- '--shard-id <id>' "$tmp/unit-shard-help"
grep -q -- '--packages <packages>' "$tmp/unit-shard-help"
"$mise_bin" -C "$root" run coverage:exclude-generated-shard --help >"$tmp/coverage-shard-help"
grep -q -- '--shard-id <id>' "$tmp/coverage-shard-help"
"$mise_bin" -C "$root" run integration:run:vm --help >"$tmp/vm-help"
grep -q -- '--test-pattern <pattern>' "$tmp/vm-help"
"$mise_bin" -C "$root" run oats-test-debug --help >"$tmp/oats-debug-help"
grep -q -- '--suite <suite>' "$tmp/oats-debug-help"
grep -q 'default.*kafka' "$tmp/oats-debug-help"

bash "$root/scripts/tests/mise-oats-native-task.sh" "$mise_bin"

# Root matrix tasks expose partitions through documented native mise usage.
# Verify help/defaults, CLI overrides, and the legacy PARTITIONS environment
# variable while keeping generated JSON as the entire stdout stream.
mkdir -p "$tmp/matrix-bin"
cat >"$tmp/matrix-bin/go" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$*" == 'list -mod vendor ./...' ]] || {
  echo "unexpected go invocation in matrix fixture: $*" >&2
  exit 1
}
# Delay discovery to expose consumers that exit without reading stdin.
sleep 0.05
printf '%s\n' ./pkg/alpha ./pkg/beta ./pkg/gamma
SH
cat >"$tmp/matrix-bin/gotestsum" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ ${1-} == tool && ${2-} == ci-matrix ]] || {
  echo "unexpected gotestsum invocation in matrix fixture: $*" >&2
  exit 1
}
shift 2
partitions=
timing_files=
while (($#)); do
  case "$1" in
    --partitions) partitions=${2-}; shift 2 ;;
    --timing-files=*) timing_files=$1; shift ;;
    *) echo "unexpected gotestsum matrix argument: $1" >&2; exit 1 ;;
  esac
done
[[ $partitions =~ ^[1-9][0-9]*$ && $timing_files == --timing-files=* ]] || {
  echo "missing matrix options: partitions=$partitions timing_files=$timing_files" >&2
  exit 1
}
# The real matrix command consumes the package list from stdin.
cat >/dev/null
printf '{"include":['
for ((i = 0; i < partitions; i++)); do
  if ((i > 0)); then printf ','; fi
  printf '{"id":%d}' "$i"
done
printf ']}\n'
SH
chmod +x "$tmp/matrix-bin/go" "$tmp/matrix-bin/gotestsum"

check_matrix_task() {
  local task=$1 default_partitions=$2 help_output matrix_output
  if ! help_output=$("$mise_bin" -C "$root" run --skip-tools "$task" --help 2>&1); then
    printf 'could not read help for matrix task %s:\n%s\n' "$task" "$help_output" >&2
    return 1
  fi
  if ! grep -Fq -- '--partitions <count>' <<<"$help_output" ||
    ! grep -Fq "(default: $default_partitions)" <<<"$help_output"; then
    printf 'unexpected help for matrix task %s (expected default %s):\n%s\n' \
      "$task" "$default_partitions" "$help_output" >&2
    return 1
  fi

  check_matrix_output() {
    local expected=$1 mode=$2 error_output
    local -a command=("$mise_bin" -C "$root" run --skip-tools "$task")
    local -a env_args=()
    local -a matrix_env=()
    error_output="$tmp/matrix-${task//[:\/]/_}-${mode}.stderr"
    if [[ $task == //:test:matrix ]]; then
      # The Generate workflow runs this check before cold bpf2go generation;
      # stub Go discovery and gotestsum so missing generated .o files cannot
      # make this task-argument regression depend on workflow ordering.
      matrix_env=(MISE_ENABLE_TOOLS='' PATH="$tmp/matrix-bin:$PATH")
    fi
    case "$mode" in
    cli) command+=(--partitions "$expected") ;;
    env) env_args=(PARTITIONS="$expected") ;;
    esac
    if ! matrix_output=$(env -u PARTITIONS "${env_args[@]}" "${matrix_env[@]}" TEST_OUTPUT="$tmp/matrix-output" \
      "${command[@]}" 2>"$error_output"); then
      printf 'matrix task %s failed in %s mode (partitions=%s):\n' \
        "$task" "$mode" "$expected" >&2
      cat "$error_output" >&2
      printf '%s\n' "$matrix_output" >&2
      return 1
    fi
    if ! python3 - "$matrix_output" "$expected" <<'PY'
import json
import sys
matrix = json.loads(sys.argv[1])
assert len(matrix["include"]) == int(sys.argv[2]), (len(matrix["include"]), sys.argv[2])
PY
    then
      printf 'matrix task %s returned the wrong number of partitions (expected %s):\n%s\n' \
        "$task" "$expected" "$matrix_output" >&2
      return 1
    fi
  }

  check_matrix_output "$default_partitions" default
  check_matrix_output 2 cli
  check_matrix_output 3 env
}
mkdir -p "$tmp/matrix-output"
check_matrix_task //:test:matrix 3
check_matrix_task //:integration:matrix 5
check_matrix_task //:integration:matrix:beyla 5
check_matrix_task //:integration:matrix:multiprocess 3

# Exercise compile defaults through the repository's real task template. Use
# fake Go/Git binaries to assert inherited values and Git fallback behavior
# without building binaries or requiring the configured tool versions.
mkdir -p "$tmp/compile-bin"
cat >"$tmp/compile-bin/go" <<'SH'
#!/usr/bin/env bash
printf 'GOOS=%s GOARCH=%s CMD=%s MAIN_GO_FILE=%s CACHE_CMD=%s CACHE_MAIN_GO_FILE=%s BUILDINFO_PKG=%s ARGS=%s\n' \
  "$GOOS" "$GOARCH" "$CMD" "$MAIN_GO_FILE" "$CACHE_CMD" \
  "$CACHE_MAIN_GO_FILE" "$BUILDINFO_PKG" "$*" >> "$COMPILE_LOG"
SH
cat >"$tmp/compile-bin/git" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GIT_LOG"
if [[ ${GIT_MODE:-success} == fail ]]; then exit 1; fi
case "$*" in
  'describe --all') printf 'heads/template-probe\n' ;;
  'rev-parse --short HEAD') printf 'abc123\n' ;;
  *) exit 1 ;;
esac
SH
chmod +x "$tmp/compile-bin/go" "$tmp/compile-bin/git"
for task in //:compile //:compile:cache //:compile:cache-coverage \
  //:compile:coverage //:compile:debug; do
  compile_log="$tmp/compile-${task//[:\/]/-}"
  git_log="$tmp/git-${task//[:\/]/-}"
  env -u GOOS -u GOARCH -u CMD -u MAIN_GO_FILE -u CACHE_CMD \
    -u CACHE_MAIN_GO_FILE -u RELEASE_VERSION -u RELEASE_REVISION \
    MISE_ENABLE_TOOLS='' PATH="$tmp/compile-bin:$PATH" \
    COMPILE_LOG="$compile_log" GIT_LOG="$git_log" GIT_MODE=success \
    "$mise_bin" -C "$root" run --skip-tools "$task" >/dev/null 2>/dev/null
  grep -Fq 'GOOS=linux GOARCH=amd64' "$compile_log"
  grep -Fq 'BUILDINFO_PKG=github.com/grafana/beyla/v3/pkg/buildinfo' "$compile_log"
  if [[ $task == *cache* ]]; then
    grep -Fq 'CACHE_CMD=k8s-cache CACHE_MAIN_GO_FILE=cmd/k8s-cache/main.go' "$compile_log"
  else
    grep -Fq 'CMD=beyla MAIN_GO_FILE=cmd/beyla/main.go' "$compile_log"
  fi
  if [[ $task != *cache-coverage ]]; then
    if [[ $task == *coverage ]]; then
      grep -Fq 'Version=test-template-probe' "$compile_log"
      grep -Fq 'Revision=test-abc123' "$compile_log"
    else
      grep -Fq 'Version=template-probe' "$compile_log"
      grep -Fq 'Revision=abc123' "$compile_log"
    fi
  fi
done

# A failed Git command remains nonfatal, and explicit empty/override inputs
# are preserved while preventing Git metadata fallback commands from running.
env -u RELEASE_VERSION -u RELEASE_REVISION MISE_ENABLE_TOOLS='' \
  PATH="$tmp/compile-bin:$PATH" COMPILE_LOG="$tmp/compile-failed-git" \
  GIT_LOG="$tmp/git-failed-git" GIT_MODE=fail \
  "$mise_bin" -C "$root" run --skip-tools //:compile:cache >/dev/null 2>/dev/null
grep -Fq 'Version=' "$tmp/compile-failed-git"
grep -Fq 'Revision=' "$tmp/compile-failed-git"

env MISE_ENABLE_TOOLS='' PATH="$tmp/compile-bin:$PATH" \
  COMPILE_LOG="$tmp/compile-overrides" GIT_LOG="$tmp/git-overrides" \
  GOOS='' GOARCH='' CMD='' MAIN_GO_FILE='' \
  RELEASE_VERSION=review-override RELEASE_REVISION=abc123 \
  "$mise_bin" -C "$root" run --skip-tools //:compile >/dev/null 2>/dev/null
grep -Fq 'GOOS= GOARCH= CMD= MAIN_GO_FILE=' "$tmp/compile-overrides"
grep -Fq 'Version=review-override' "$tmp/compile-overrides"
grep -Fq 'Revision=abc123' "$tmp/compile-overrides"
[[ ! -e "$tmp/git-overrides" ]]

echo 'mise naming regressions passed'
