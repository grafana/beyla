#!/bin/bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Generate test matrix - one shard per test directory
# Usage: ./scripts/generate-dir-matrix.sh [search_dir] [exclude_pattern]

set -e

# Find all test directories
SEARCH_DIR="${1:-internal/test/integration/k8s}"
EXCLUDE_PATTERN="${2:-common}"
TEST_DIRS=$(find "$SEARCH_DIR" -name "*_test.go" | grep -v "$EXCLUDE_PATTERN" | sort | xargs dirname | xargs basename -a | sort -u)

if [ -z "$TEST_DIRS" ]; then
    echo "ERROR: No test directories found in $SEARCH_DIR" >&2
    exit 1
fi

# Count directories
DIR_COUNT=$(echo "$TEST_DIRS" | wc -l | tr -d ' ')
echo "Total test packages: $DIR_COUNT" >&2

# Generate matrix JSON
MATRIX_JSON='{"include":['
FIRST=true
SHARD_ID=0

for dir in $TEST_DIRS; do
    if [ "$FIRST" = "false" ]; then
        MATRIX_JSON+=","
    fi
    FIRST=false
    
    # Each shard runs all tests in its package directory
    MATRIX_JSON+="{\"id\":$SHARD_ID,\"basename\":\"$dir\",\"test_pattern\":\"./$SEARCH_DIR/$dir/...\"}"
    
    echo "Shard $SHARD_ID: $dir" >&2
    
    SHARD_ID=$((SHARD_ID + 1))
done

MATRIX_JSON+=']}'
echo "$MATRIX_JSON"