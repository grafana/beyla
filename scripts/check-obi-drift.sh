#!/usr/bin/env bash
# Detect and optionally sync test functions that have drifted between Beyla and OBI
#
# Usage:
#   ./scripts/check-obi-drift.sh           # Check for drift (exit 1 if found)
#   ./scripts/check-obi-drift.sh --sync    # Apply OBI changes to Beyla files
#   ./scripts/check-obi-drift.sh --help    # Show help

set -euo pipefail

OBI_DIR=".obi-src/internal/test/integration"
BEYLA_DIR="internal/test/integration"
SYNC_MODE=false

# Find test functions and helper functions that exist in both Beyla and OBI
find_common_functions() {
    # Get function names from both directories
    # Match both test functions (testXxx) and test helper functions (functions taking *testing.T)
    local beyla_funcs=$(grep -rh "^func [a-z][a-zA-Z0-9_]*(" "$BEYLA_DIR"/*.go 2>/dev/null | \
        grep -E '\*testing\.(T|B)\b' | \
        sed 's/^func \([a-zA-Z0-9_]*\).*/\1/' | sort -u)
    
    local obi_funcs=$(grep -rh "^func [a-z][a-zA-Z0-9_]*(" "$OBI_DIR"/*.go 2>/dev/null | \
        grep -E '\*testing\.(T|B)\b' | \
        sed 's/^func \([a-zA-Z0-9_]*\).*/\1/' | sort -u)
    
    # Find common functions
    comm -12 <(echo "$beyla_funcs") <(echo "$obi_funcs")
}

# Extract function body from a file
extract_function() {
    local func="$1"
    local file="$2"
    
    # Extract function from start to closing brace at column 0
    # Use \( to match the opening parenthesis and avoid matching function name prefixes
    sed -n "/^func $func(/,/^}/p" "$file"
}

# Find which file contains a function in a directory
find_function_file() {
    local func="$1"
    local dir="$2"
    
    grep -l "^func $func(" "$dir"/*.go 2>/dev/null | head -1
}

# Sync function from OBI to Beyla
sync_function() {
    local func="$1"
    local beyla_file="$2"
    local obi_file="$3"
    
    echo "  Syncing $func from OBI..."
    
    # Create temp file with transformed function
    local temp_func=$(mktemp)
    
    # Extract the OBI function body and transform for Beyla
    extract_function "$func" "$obi_file" | \
        sed 's|go.opentelemetry.io/obi|github.com/grafana/beyla|g' | \
        sed 's|obi_|beyla_|g' | \
        sed 's|service_name="opentelemetry-ebpf-instrumentation"|service_name="beyla"|g' | \
        sed 's|telemetry.sdk.name", Type: "string", Value: "opentelemetry-ebpf-instrumentation"|telemetry.sdk.name", Type: "string", Value: "beyla"|g' \
        > "$temp_func"
    
    # Use go run with flags (avoids *_test.go file path parsing issues)
    local script_dir="$(dirname "$0")"
    go run "$script_dir/replace-function.go" -file "$beyla_file" -func "$func" -new "$temp_func"
    
    # Clean up
    rm -f "$temp_func"
    
    echo "  ✓ Synced $func in ${beyla_file##*/}"
}

# Check if a function uses the shared test package
is_using_shared_package() {
    local func="$1"
    local file="$2"
    
    # Check if the file imports OBI's shared test integration package and extract the alias
    local alias=$(grep "go\.opentelemetry\.io/obi/pkg/test/integration" "$file" 2>/dev/null | \
        sed -n 's/^[[:space:]]*\([[:alpha:]][[:alnum:]]*\)[[:space:]]*"go\.opentelemetry\.io\/obi\/pkg\/test\/integration".*/\1/p' | head -1)
    
    if [[ -n "$alias" ]]; then
        # Check if the function body actually uses the shared package via the alias
        local func_body=$(extract_function "$func" "$file")
        if echo "$func_body" | grep -qE "${alias}\.[A-Z][[:alpha:]]*\("; then
            return 0  # Uses shared package
        fi
    fi
    return 1  # Not using shared package
}

# Compare function implementations
check_drift() {
    local func="$1"
    
    # Find files containing this function
    local beyla_file=$(find_function_file "$func" "$BEYLA_DIR")
    local obi_file=$(find_function_file "$func" "$OBI_DIR")
    
    if [[ -z "$beyla_file" ]] || [[ -z "$obi_file" ]]; then
        return 0  # Skip if not found in both
    fi
    
    # Check if Beyla's version uses the shared test package
    if is_using_shared_package "$func" "$beyla_file"; then
        # Function has been migrated to use shared package - no drift possible
        return 0
    fi
    
    # Extract function bodies
    local beyla_body=$(extract_function "$func" "$beyla_file")
    local obi_body=$(extract_function "$func" "$obi_file")
    
    # Normalize to ignore copyright, import path, and metric name changes
    local beyla_normalized=$(echo "$beyla_body" | \
        grep -v "Copyright The OpenTelemetry Authors" | \
        grep -v "SPDX-License-Identifier: Apache-2.0" | \
        sed 's|github.com/grafana/beyla|go.opentelemetry.io/obi|g' | \
        sed 's|beyla_|obi_|g' | \
        sed 's|service_name="beyla"|service_name="opentelemetry-ebpf-instrumentation"|g' | \
        sed 's|telemetry.sdk.name", Type: "string", Value: "beyla"|telemetry.sdk.name", Type: "string", Value: "opentelemetry-ebpf-instrumentation"|g')
    local obi_normalized=$(echo "$obi_body" | \
        grep -v "Copyright The OpenTelemetry Authors" | \
        grep -v "SPDX-License-Identifier: Apache-2.0")
    
    if [[ "$beyla_normalized" != "$obi_normalized" ]]; then
        echo "$func"
        echo "  Beyla: ${beyla_file##*/}"
        echo "  OBI:   ${obi_file##*/}"
        echo ""
        
        if [[ "$SYNC_MODE" == "true" ]]; then
            sync_function "$func" "$beyla_file" "$obi_file"
        else
            # Show color-coded diff using normalized versions
            diff -u \
                <(echo "$beyla_normalized") \
                <(echo "$obi_normalized") 2>/dev/null | \
                sed 's/^-/\x1b[31m-/; s/^+/\x1b[32m+/; s/^@/\x1b[36m@/; s/$/\x1b[0m/' || true
        fi
        
        echo ""
        return 1
    fi
    
    return 0
}

# Show help
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Check for drift between Beyla and OBI test functions, and optionally sync them.

Options:
  --sync    Apply OBI changes to Beyla files
  --help    Show this help message

Examples:
  # Check for drift (exit 1 if any found)
  $0

  # Apply OBI changes to Beyla files
  $0 --sync

When --sync is used:
  - Replaces drifted Beyla functions with OBI versions
  - Creates a git-ready changeset
  - You can review changes with 'git diff' and create a PR

EOF
}

# Count inline usage of shared package functions in test suites
count_inline_shared_usage() {
    # Count unique shared package function calls by extracting the actual import alias
    # First, find a file that imports the package and extract the alias
    local alias=""
    for file in "$BEYLA_DIR"/*.go; do
        alias=$(grep "go\.opentelemetry\.io/obi/pkg/test/integration" "$file" 2>/dev/null | \
            sed -n 's/^[[:space:]]*\([[:alpha:]][[:alnum:]]*\)[[:space:]]*"go\.opentelemetry\.io\/obi\/pkg\/test\/integration".*/\1/p' | head -1)
        if [[ -n "$alias" ]]; then
            break
        fi
    done
    
    if [[ -z "$alias" ]]; then
        echo "0"
        return
    fi
    
    # Now search all files at once for function calls using that alias
    grep -roh "${alias}\.[A-Z][[:alpha:]]*(" "$BEYLA_DIR"/*.go 2>/dev/null | \
        sed 's/($//' | sort -u | wc -l | tr -d ' ' || echo "0"
}

# Main
main() {
    if [[ "$SYNC_MODE" == "true" ]]; then
        echo "Syncing drifted test functions from OBI to Beyla..."
    else
        echo "Checking for drift between Beyla and OBI test functions..."
    fi
    echo ""
    
    local common_funcs=$(find_common_functions)
    local total=0
    local drifted=0
    
    for func in $common_funcs; do
        total=$((total + 1))
        
        # Check if drifted (skip if using shared package, as those can't drift)
        local beyla_file=$(find_function_file "$func" "$BEYLA_DIR")
        if [[ -n "$beyla_file" ]] && is_using_shared_package "$func" "$beyla_file"; then
            # Function uses shared package - skip drift check
            continue
        elif ! check_drift "$func"; then
            drifted=$((drifted + 1))
        fi
    done
    
    # Count inline usage of shared package (e.g., ti.InternalPrometheusExport)
    local inline_shared=$(count_inline_shared_usage)
    
    echo "Summary:"
    echo "  - Total common functions: $total"
    if [[ $inline_shared -gt 0 ]]; then
        echo "  - Using shared package: $inline_shared unique function calls"
    fi
    echo "  - Drifted from OBI: $drifted"
    echo "  - In sync: $((total - drifted))"
    
    if [[ $drifted -gt 0 ]]; then
        echo ""
        if [[ "$SYNC_MODE" == "true" ]]; then
            echo "✓ Synced $drifted functions from OBI"
            echo ""
            echo "Next steps:"
            echo "  1. Review changes: git diff internal/test/integration/"
            echo "  2. Run tests: go test -tags=integration ./internal/test/integration/..."
            echo "  3. Create PR: git add internal/test/integration/ && git commit -m 'Sync tests from OBI'"
        else
            echo "To sync these changes automatically:"
            echo "  $0 --sync"
            echo ""
            echo "To migrate a function to use the shared package instead:"
            echo "  See internal/test/integration/suites_test.go for inline usage example"
            echo ""
            echo "To see full diff for a function:"
            echo "  diff -u internal/test/integration/traces_test.go .obi-src/internal/test/integration/traces_test.go"
            exit 1
        fi
    fi
}

# Parse arguments
case "${1:-}" in
    --sync)
        SYNC_MODE=true
        ;;
    --help)
        show_help
        exit 0
        ;;
    "")
        # Default: check mode
        ;;
    *)
        echo "Error: Unknown option: $1"
        echo ""
        show_help
        exit 1
        ;;
esac

main

