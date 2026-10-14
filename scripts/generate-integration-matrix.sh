#!/bin/bash

# Generate standard test matrix with configurable partitions using LPT
# (Longest Processing Time) bin packing for balanced shard execution times.
#
# Usage: ./scripts/generate-integration-matrix.sh [test_tags] [search_dir] [partitions] [test_pattern]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_TAGS="${1:-integration}"
SEARCH_DIR="${2:-internal/test/integration}"
PARTITIONS="${3:-5}"
TEST_PATTERN="${4:-Test}"
WEIGHTS_FILE="${WEIGHTS_FILE:-$SCRIPT_DIR/integration-test-weights.generated.json}"

# Get test names
if [ -n "$TEST_TAGS" ]; then
    # Find files with the specific build tag (exact match with word boundaries)
    FILES=$(find "$SEARCH_DIR" -maxdepth 1 -type f -name "*_test.go" -exec grep -l "//go:build.*\b$TEST_TAGS\b" {} \;)
else
    # Find all test files
    FILES=$(find "$SEARCH_DIR" -maxdepth 1 -type f -name "*_test.go")
fi

if [ -z "$FILES" ]; then
    echo "No test files found" >&2
    exit 1
fi

# Extract test function names from the files and sort
TEST_NAMES=$(grep -h "^func $TEST_PATTERN" $FILES | sed 's/^func \([^(]*\).*/\1/' | sort -u)

if [ -z "$TEST_NAMES" ]; then
    echo "ERROR: No tests found for tags '$TEST_TAGS' in '$SEARCH_DIR'" >&2
    exit 1
fi

TOTAL_TESTS=$(echo "$TEST_NAMES" | wc -l | tr -d " ")

# Look up weights and assign tests to shards using LPT (Longest Processing Time)
# bin packing: sort tests by weight descending, assign each to the lightest shard.
if [ -f "$WEIGHTS_FILE" ] && command -v jq >/dev/null 2>&1; then
    DEFAULT_WEIGHT=$(jq -r '._default // 20' "$WEIGHTS_FILE")

    # Build "weight testname" pairs, sorted by weight descending then name
    WEIGHTED_TESTS=$(echo "$TEST_NAMES" | while read -r name; do
        w=$(jq -r --arg n "$name" '.[$n] // empty' "$WEIGHTS_FILE")
        if [ -z "$w" ]; then
            w=$DEFAULT_WEIGHT
        fi
        echo "$w $name"
    done | sort -k1,1 -rn -k2,2)

    echo "Using weighted bin packing (weights from $WEIGHTS_FILE)" >&2
else
    # Fallback: equal weights, alphabetical order
    DEFAULT_WEIGHT=20
    WEIGHTED_TESTS=$(echo "$TEST_NAMES" | while read -r name; do
        echo "$DEFAULT_WEIGHT $name"
    done)

    echo "Warning: weights file not found or jq not available, using equal weights" >&2
fi

# LPT bin packing via awk: assign each test (sorted heaviest first) to the
# shard with the smallest accumulated weight.
SHARD_ASSIGNMENTS=$(echo "$WEIGHTED_TESTS" | awk -v partitions="$PARTITIONS" '
BEGIN {
    for (i = 0; i < partitions; i++) {
        shard_weight[i] = 0
    }
}
{
    weight = $1
    name = $2

    # Find the shard with the smallest total weight
    min_shard = 0
    min_weight = shard_weight[0]
    for (i = 1; i < partitions; i++) {
        if (shard_weight[i] < min_weight) {
            min_weight = shard_weight[i]
            min_shard = i
        }
    }

    shard_weight[min_shard] += weight
    print min_shard, weight, name
}
END {
    for (i = 0; i < partitions; i++) {
        printf "Shard %d estimated weight: %ds\n", i, shard_weight[i] > "/dev/stderr"
    }
}')

echo "Total tests matching '$TEST_PATTERN': $TOTAL_TESTS, Partitions: $PARTITIONS" >&2

# Generate matrix JSON from shard assignments
MATRIX_JSON='{"include":['
FIRST_SHARD=true

for SHARD in $(seq 0 $((PARTITIONS - 1))); do
    SHARD_TESTS=$(echo "$SHARD_ASSIGNMENTS" | awk -v s="$SHARD" '$1 == s { print $3 }' | tr "\n" "|" | sed "s/|$//")

    if [ -n "$SHARD_TESTS" ]; then
        if [ "$FIRST_SHARD" = "false" ]; then
            MATRIX_JSON+=","
        fi
        FIRST_SHARD=false

        TEST_COUNT=$(echo "$SHARD_TESTS" | tr "|" "\n" | wc -l | tr -d " ")
        MATRIX_JSON+="{\"id\":$SHARD,\"description\":\"shard-$SHARD ($TEST_COUNT tests)\",\"test_pattern\":\"$SHARD_TESTS\"}"

        echo "Shard $SHARD: $TEST_COUNT tests: $SHARD_TESTS" >&2
    fi
done

MATRIX_JSON+=']}'
echo "$MATRIX_JSON"
