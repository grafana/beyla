#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Regenerate integration-test-weights.json from downloaded GitHub Actions logs.
#
# Usage:
#   1. Download logs from a CI run (Actions tab -> workflow run -> download logs)
#   2. Extract the zip into a directory
#   3. Run: ./scripts/update-test-weights.sh <logs-directory>
#
# Example:
#   ./scripts/update-test-weights.sh tmplogs/logs_57563497044

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEIGHTS_FILE="$SCRIPT_DIR/integration-test-weights.generated.json"
DEFAULT_WEIGHT=20

if [ $# -lt 1 ]; then
    echo "Usage: $0 <logs-directory>" >&2
    echo "  logs-directory: path to extracted GitHub Actions runner logs" >&2
    exit 1
fi

LOGS_DIR="$1"

if [ ! -d "$LOGS_DIR" ]; then
    echo "Error: '$LOGS_DIR' is not a directory" >&2
    exit 1
fi

# Extract top-level test durations from shard log files.
# Matches lines like: PASS internal/test/integration.TestFoo (123.45s)
# The sed pattern requires a space after the test name, which excludes subtests
# (they have / after the test name). Re-runs are also excluded.
# Takes the last (aggregate) duration per test name.
ENTRIES=$(
    grep -rhE '(PASS|FAIL).*integration\.Test' "$LOGS_DIR"/*shard*.txt 2>/dev/null \
    | grep -v '^ ' \
    | grep -v 're-run' \
    | sed -n 's/.*integration\.\(Test[A-Za-z0-9_]*\) (\([0-9.]*\)s).*/\1 \2/p' \
    | awk '{ val[$1] = int($2 + 0.5) } END { for (k in val) printf "%s %d\n", k, val[k] }' \
    | sort
) || true # ignore errors so that we can report the error below

if [ -z "$ENTRIES" ]; then
    echo "Error: no test results found in files matching '$LOGS_DIR/*shard*.txt'" >&2
    exit 1
fi

TOTAL=$(echo "$ENTRIES" | wc -l | tr -d ' ')
echo "Found $TOTAL tests in logs" >&2

# Build JSON
{
    echo "{"
    echo "  \"_default\": $DEFAULT_WEIGHT,"
    echo "$ENTRIES" | awk -v total="$TOTAL" '
    {
        count++
        if (count < total) {
            printf "  \"%s\": %s,\n", $1, $2
        } else {
            printf "  \"%s\": %s\n", $1, $2
        }
    }'
    echo "}"
} > "$WEIGHTS_FILE"

echo "Updated $WEIGHTS_FILE with $TOTAL tests" >&2
