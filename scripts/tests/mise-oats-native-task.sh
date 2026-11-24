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
mkdir -p "$fixture/internal/test/oats" "$fixture/internal/testgenerated/oats" \
  "$fixture/scripts" \
  "$fixture/.tools/oats" "$fixture/.obi-src/scripts" "$tmp/bin"
for suite in sql mongo redis kafka http memcached ai nats amqp; do
  mkdir -p "$fixture/internal/testgenerated/oats/$suite"
  printf 'meta:\n  version: 3\ncases: []\n' >"$fixture/internal/testgenerated/oats/$suite/oats-config.yaml"
done

cp "$root/internal/test/oats/mise.toml" "$fixture/internal/test/oats/mise.toml"
cp "$root/scripts/generate-dir-matrix.sh" "$fixture/scripts/generate-dir-matrix.sh"
cat >"$fixture/mise.toml" <<EOF
monorepo_root = true

[monorepo]
config_roots = ["internal/test/oats"]

[monorepo.path_aliases]
oats = "internal/test/oats"

[env]
TEST_OUTPUT = "$tmp/output"

[tasks."vendor:obi"]
run = "true"

[tasks."submodule:obi"]
run = "true"
EOF
cat >"$fixture/.obi-src/scripts/run-oats-with-log.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
log=$1
shift
mkdir -p "$(dirname "$log")"
"$@" 2>&1 | tee "$log"
EOF
cat >"$fixture/.obi-src/scripts/install-oats-tools.sh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$fixture/.tools/oats/oats" <<'EOF'
#!/usr/bin/env bash
printf '%s|%s|%s|%s\n' "$PWD" "$*" "${OATS_ARTIFACT_DIR:-}" "$TESTCASE_TIMEOUT" >>"$OATS_CALL_LOG"
echo 'OATS mock run'
EOF
cat >"$fixture/.tools/oats/gcx" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$tmp/bin/go" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$fixture/.obi-src/scripts/run-oats-with-log.sh" "$fixture/.obi-src/scripts/install-oats-tools.sh" \
  "$fixture/.tools/oats/oats" \
  "$fixture/.tools/oats/gcx" "$tmp/bin/go" "$tmp/bin/docker"

cat >"$tmp/empty-global.toml" <<'EOF'
[settings]
auto_install = false
EOF

run_mise() {
  env \
    MISE_GLOBAL_CONFIG_FILE="$tmp/empty-global.toml" \
    MISE_DATA_DIR="$tmp/mise-data" \
    MISE_CACHE_DIR="$tmp/mise-cache" \
    MISE_STATE_DIR="$tmp/mise-state" \
    MISE_TRUSTED_CONFIG_PATHS="$fixture" \
    MISE_ENABLE_TOOLS='' \
    MISE_AUTO_INSTALL=0 \
    OATS_CALL_LOG="$tmp/oats.log" \
    PATH="$tmp/bin:$PATH" \
    "$mise_bin" -C "$fixture" run --skip-tools --no-deps "$@"
}

all_suites=(sql mongo redis kafka http memcached ai nats amqp)
for suite in "${all_suites[@]}"; do
  run_mise "//oats:test:$suite"
done
python3 - "$tmp/oats.log" "$fixture" "${all_suites[@]}" <<'PY'
import pathlib
import sys

log, fixture, *expected = sys.argv[1:]
fixture = pathlib.Path(fixture)
rows = [line.split("|") for line in pathlib.Path(log).read_text().splitlines()]
assert len(rows) == len(expected), (len(rows), expected, rows)
for row, suite in zip(rows, expected, strict=True):
    cwd, args, artifacts, timeout = row
    assert cwd == str(fixture / "internal/testgenerated/oats" / suite), (suite, cwd)
    assert args == "run --config oats-config.yaml --container-runtime docker --gcx ../../../../.tools/oats/gcx --timeout 5m --absent-timeout 10s --no-cache -vvv", (suite, args)
    assert artifacts == str(fixture / "internal/testgenerated/oats" / suite / "build"), (suite, artifacts)
    assert timeout == "5m", (suite, timeout)
    assert (fixture / "internal/testgenerated/oats" / suite / "build/oats.log").is_file()
PY

mkdir -p "$fixture/internal/testgenerated/oats/common"
cp "$fixture/internal/testgenerated/oats/sql/oats-config.yaml" \
  "$fixture/internal/testgenerated/oats/common/oats-config.yaml"
matrix=$(run_mise //oats:matrix)
python3 - "$matrix" "${all_suites[@]}" <<'PY'
import json
import sys

matrix, *expected = sys.argv[1:]
observed = json.loads(matrix)["include"]
expected.append("common")
assert sorted(row["basename"] for row in observed) == sorted(expected), observed
PY

echo 'native OATS CLI task composition passed'
