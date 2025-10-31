#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Generate standard test matrix with configurable partitions
# Usage: ./scripts/generate-integration-matrix.sh [test_tags] [search_dir] [partitions] [test_pattern]

set -e

TEST_TAGS="${1:-integration}"
SEARCH_DIR="${2:-internal/test/integration}"
PARTITIONS="${3:-5}"
TEST_PATTERN="${4:-Test}"

# Get test names (embedded list-tests.sh logic)
if [ -n "$TEST_TAGS" ]; then
    # Find files with the specific build tag (exact match with word boundaries)
    FILES=$(find "$SEARCH_DIR" -type f -name "*_test.go" -exec grep -l "//go:build.*\b$TEST_TAGS\b" {} \;)
else
    # Find all test files
    FILES=$(find "$SEARCH_DIR" -type f -name "*_test.go")
fi

if [ -z "$FILES" ]; then
    echo "No test files found" >&2
    exit 1
fi

# Extract test function names from the files and randomize order
TEST_NAMES=$(grep -h "^func $TEST_PATTERN" $FILES | sed 's/^func \([^(]*\).*/\1/' | sort -u | sort -R)

if [ -z "$TEST_NAMES" ]; then
    echo "ERROR: No tests found for tags '$TEST_TAGS' in '$SEARCH_DIR'" >&2
    exit 1
fi

TOTAL_TESTS=$(echo "$TEST_NAMES" | wc -l | tr -d " ")

BASE_TESTS_PER_SHARD=$((TOTAL_TESTS / PARTITIONS))
EXTRA_TESTS=$((TOTAL_TESTS % PARTITIONS))

echo "Total tests matching '$TEST_PATTERN': $TOTAL_TESTS, Base tests per shard: $BASE_TESTS_PER_SHARD, Extra tests: $EXTRA_TESTS" >&2

# Generate matrix JSON
MATRIX_JSON='{"include":['
SHARD=0
FIRST_SHARD=true
CURRENT_START=1

while [ $SHARD -lt $PARTITIONS ]; do
    TESTS_IN_THIS_SHARD=$BASE_TESTS_PER_SHARD
    if [ $SHARD -lt $EXTRA_TESTS ]; then
        TESTS_IN_THIS_SHARD=$((TESTS_IN_THIS_SHARD + 1))
    fi
    
    START=$CURRENT_START
    END=$((CURRENT_START + TESTS_IN_THIS_SHARD - 1))
    SHARD_TESTS=$(echo "$TEST_NAMES" | sed -n "${START},${END}p" | tr "\n" "|" | sed "s/|$//")
    
    if [ ! -z "$SHARD_TESTS" ]; then
        if [ "$FIRST_SHARD" = "false" ]; then
            MATRIX_JSON+=","
        fi
        FIRST_SHARD=false
        
        TEST_COUNT=$(echo "$SHARD_TESTS" | tr "|" "\n" | wc -l | tr -d " ")
        MATRIX_JSON+="{\"id\":$SHARD,\"description\":\"shard-$SHARD ($TEST_COUNT tests)\",\"test_pattern\":\"$SHARD_TESTS\"}"
        
        echo "Shard $SHARD: $TEST_COUNT tests" >&2
    fi
    
    CURRENT_START=$((END + 1))
    SHARD=$((SHARD + 1))
done

MATRIX_JSON+=']}'
echo "$MATRIX_JSON"
