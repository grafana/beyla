#!/usr/bin/env bash
set -euo pipefail

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
echo "checking task naming with $version"

# Every historical spelling should resolve to the same dry-run plan as its new
# task identity. Nothing is actually run and --skip-tools avoids tool installs.
check_task() {
  local old_name=$1 expected=$2 actual expected_output
  # Composite tasks need not print their own task ID (only their dependencies),
  # so compare the execution plan with the explicit canonical task identity.
  actual=$("$mise_bin" -C "$root" run --dry-run --skip-tools "$old_name" 2>&1 | grep -F '] $ ' || true)
  expected_output=$("$mise_bin" -C "$root" run --dry-run --skip-tools "$expected" 2>&1 | grep -F '] $ ' || true)
  if [[ -z "$actual" || "$actual" != "$expected_output" ]]; then
    printf 'legacy task %q did not resolve to %q; actual plan:\n%s\nexpected plan:\n%s\n' \
      "$old_name" "$expected" "$actual" "$expected_output" >&2
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
check_task test:unit-shard //:test:shard
check_task run-unit-test-shard //:test:shard

# No moved task should be duplicated as a public root wrapper. --all is needed
# to see monorepo children, but task identity still distinguishes root from the
# named child config.
"$mise_bin" -C "$root" tasks ls --all --json > "$tmp/tasks.json"
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
"$mise_bin" -C "$root" run --dry-run --skip-tools java-build > "$tmp/java-build-plan" 2>&1
grep -Fq '.mise/tasks/build' "$tmp/java-build-plan"
"$mise_bin" -C "$root" run --dry-run --skip-tools oats-test-debug > "$tmp/oats-debug-plan" 2>&1
grep -Fq 'internal/test/oats/.mise/tasks/debug' "$tmp/oats-debug-plan"

echo 'mise naming regressions passed'
