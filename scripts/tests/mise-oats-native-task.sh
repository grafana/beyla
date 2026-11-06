#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mise_bin=${1:-${MISE_BIN:-$(command -v mise || true)}}
if [[ -z "$mise_bin" || ! -x "$mise_bin" ]]; then
  echo 'mise-oats-native-task requires an installed mise binary (set MISE_BIN)' >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fixture="$tmp/repo"
mkdir -p "$fixture/internal/test/oats" "$fixture/internal/testgenerated/oats" "$tmp/bin"
for suite in sql mongo redis kafka http memcached ai nats amqp; do
  mkdir -p "$fixture/internal/testgenerated/oats/$suite"
done

# Run the real OATS task config in a temporary monorepo. Replace only its root
# vendor and coverage dependencies with logging no-ops, and mock Ginkgo so this
# checks task composition without generating OBI or running integration tests.
cp "$root/internal/test/oats/mise.toml" "$fixture/internal/test/oats/mise.toml"
cat > "$fixture/mise.toml" <<EOF
monorepo_root = true

[monorepo]
config_roots = ["internal/test/oats"]

[monorepo.path_aliases]
oats = "internal/test/oats"

[env]
TEST_OUTPUT = "$tmp/output"

[tasks."vendor:obi"]
run = 'echo prepare >> "\$OATS_PREP_LOG"'

[tasks."integration:coverage-data"]
run = 'echo coverage >> "\$OATS_COVERAGE_LOG"'
EOF
cat > "$tmp/empty-global.toml" <<'EOF'
[settings]
auto_install = false
EOF
cat > "$tmp/bin/ginkgo" <<'EOF'
#!/usr/bin/env bash
printf '%s|%s|%s|%s|%s|%s\n' \
  "${PWD##*/}" "$PWD" "$*" "$TESTCASE_BASE_PATH" "$TESTCASE_TIMEOUT" "$TEST_OUTPUT" \
  >> "$OATS_GINKGO_LOG"
EOF
chmod +x "$tmp/bin/ginkgo"

run_mise() {
  env \
    MISE_GLOBAL_CONFIG_FILE="$tmp/empty-global.toml" \
    MISE_DATA_DIR="$tmp/mise-data" \
    MISE_CACHE_DIR="$tmp/mise-cache" \
    MISE_STATE_DIR="$tmp/mise-state" \
    MISE_TRUSTED_CONFIG_PATHS="$fixture" \
    MISE_ENABLE_TOOLS='' \
    MISE_AUTO_INSTALL=0 \
    OATS_PREP_LOG="$tmp/prepare.log" \
    OATS_COVERAGE_LOG="$tmp/coverage.log" \
    OATS_GINKGO_LOG="$tmp/ginkgo.log" \
    OATS_GINKGO="$tmp/bin/ginkgo" \
    "$mise_bin" -C "$fixture" run --skip-tools "$@"
}

check_suites() {
  python3 - "$tmp/ginkgo.log" "$fixture" "$tmp/output" "$@" <<'PY'
import pathlib
import sys

log, fixture, output, *expected = sys.argv[1:]
fixture, output = pathlib.Path(fixture), pathlib.Path(output)
rows = [line.split("|") for line in pathlib.Path(log).read_text().splitlines()]
assert len(rows) == len(expected), (len(rows), expected, rows)
observed = [row[0] for row in rows]
assert sorted(observed) == sorted(expected), (observed, expected)
for suite, cwd, args, base_path, timeout, test_output in rows:
    assert cwd == str(fixture / "internal/testgenerated/oats" / suite), (suite, cwd)
    assert args == "-v -r", (suite, args)
    assert base_path == "./yaml", (suite, base_path)
    assert timeout == "5m", (suite, timeout)
    assert test_output == str(output), (suite, test_output)
assert (output / "run").is_dir(), output
PY
}

all_suites=(sql mongo redis kafka http memcached ai nats amqp)
run_mise //oats:test
check_suites "${all_suites[@]}"
[[ $(wc -l < "$tmp/prepare.log") -eq 1 ]]
[[ $(wc -l < "$tmp/coverage.log") -eq 1 ]]

: > "$tmp/ginkgo.log"
: > "$tmp/prepare.log"
run_mise --jobs 2 //oats:test:sql ::: //oats:test:ai
check_suites sql ai
[[ $(wc -l < "$tmp/prepare.log") -eq 1 ]]

: > "$tmp/ginkgo.log"
if run_mise //oats:_suite ../escape >"$tmp/invalid-suite.log" 2>&1; then
  echo 'OATS suite helper accepted a path outside its allowlist' >&2
  exit 1
fi
grep -q 'Invalid choice for arg suite' "$tmp/invalid-suite.log"
[[ ! -s "$tmp/ginkgo.log" ]]

echo 'native OATS task composition passed'
