#!/usr/bin/env bash
# Detect and optionally sync test functions and components that have drifted between Beyla and OBI
#
# Usage:
#   ./scripts/check-obi-drift.sh           # Check for drift (exit 1 if found)
#   ./scripts/check-obi-drift.sh --sync    # Apply OBI changes to Beyla files
#   ./scripts/check-obi-drift.sh --help    # Show help

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

OBI_DIR=".obi-src/internal/test/integration"
BEYLA_DIR="internal/test/integration"

# Component directory name mappings (OBI name -> Beyla name)
declare -A COMPONENT_DIR_MAP=(
    ["ebpf-instrument"]="beyla"
    ["ebpf-instrument-k8s-cache"]="beyla-k8s-cache"
)

# File patterns to check (regex)
INCLUDE_EXTENSIONS='py|go|sh|rb|java|js|ts|rs|c|h|yaml|yml|json'
INCLUDE_SPECIAL='^Dockerfile|^Makefile'

# Patterns to skip
SKIP_DIRS='vendor|node_modules|\.git|__pycache__|target|build'
SKIP_FILES='go\.mod$|go\.sum$'  # Intentionally different between projects

# OBI -> Beyla text transformations (applied via sed)
# Format: "pattern|replacement" - order matters, more specific patterns first
TRANSFORMATIONS=(
    'OTEL_EBPF_|BEYLA_'
    'otel-ebpf|beyla'
    'otel_ebpf|beyla'
    'go\.opentelemetry\.io/obi|github.com/grafana/beyla/v2'
    'obi-k8s-test-cluster|beyla-k8s-test-cluster'
    'obi-config-|instrumenter-config-'
    'obi_|beyla_'
    'hatest-obi|hatest-autoinstrumenter'
    'opentelemetry-ebpf-instrumentation|beyla'
    'ebpf-instrument/Dockerfile|beyla/Dockerfile'
    'components/ebpf-instrument|components/beyla'
    'ebpf-instrument:|autoinstrumenter:'
    'service:ebpf-instrument|service:autoinstrumenter'
    'image: hatest-ebpf-instrument|image: hatest-autoinstrumenter'
    'obi:|autoinstrumenter:'
    'service:obi|service:autoinstrumenter'
    '// OBI |// Beyla '
    '# OBI |# Beyla '
)

# Reverse transformations for comparison (Beyla -> OBI)
REVERSE_TRANSFORMATIONS=(
    'BEYLA_|OTEL_EBPF_'
    'github\.com/grafana/beyla/v2|go.opentelemetry.io/obi'
    'beyla-k8s-test-cluster|obi-k8s-test-cluster'
    'beyla_|obi_'
    'hatest-autoinstrumenter|hatest-obi'
    'autoinstrumenter:|obi:'
    'service:autoinstrumenter|service:obi'
)

# =============================================================================
# GLOBALS
# =============================================================================

SYNC_MODE=false
VERBOSE=false
TOTAL_DRIFT=0

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Build sed expression from transformation array
build_sed_expr() {
    local -n transforms=$1
    local expr=""
    for t in "${transforms[@]}"; do
        local pattern="${t%%|*}"
        local replacement="${t#*|}"
        expr+=" -e 's|${pattern}|${replacement}|g'"
    done
    echo "$expr"
}

# Transform OBI content to Beyla conventions
transform_obi_to_beyla() {
    eval "sed $(build_sed_expr TRANSFORMATIONS)"
}

# Transform Beyla content to OBI conventions (for comparison)
transform_beyla_to_obi() {
    eval "sed $(build_sed_expr REVERSE_TRANSFORMATIONS)"
}

# Normalize content for comparison (strip copyright, trailing whitespace)
normalize_content() {
    grep -v "Copyright The OpenTelemetry Authors" | \
    grep -v "SPDX-License-Identifier:" | \
    grep -v "^[[:space:]]*#.*Copyright" | \
    grep -v "^[[:space:]]*//.*Copyright" | \
    sed 's/[[:space:]]*$//' | \
    cat -s
}

# Check if file should be compared
should_check_file() {
    local file="$1"
    local basename="${file##*/}"
    
    # Skip excluded directories
    echo "$file" | grep -qE "/($SKIP_DIRS)/" && return 1
    
    # Skip excluded file patterns
    echo "$basename" | grep -qE "$SKIP_FILES" && return 1
    
    # Include by extension or special name
    echo "$basename" | grep -qE "\.($INCLUDE_EXTENSIONS)$|$INCLUDE_SPECIAL"
}

# Map OBI path to Beyla path
map_path() {
    local path="$1"
    
    # Replace base directories
    path="${path//$OBI_DIR/$BEYLA_DIR}"
    
    # Apply component directory mappings
    for obi_name in "${!COMPONENT_DIR_MAP[@]}"; do
        local beyla_name="${COMPONENT_DIR_MAP[$obi_name]}"
        path="${path//\/$obi_name\///$beyla_name/}"
    done
    
    # Transform config filenames
    path="${path//obi-config-/instrumenter-config-}"
    
    echo "$path"
}

# =============================================================================
# GENERIC DRIFT CHECKING
# =============================================================================

# Check if two files have drifted (after normalization)
files_have_drifted() {
    local obi_file="$1"
    local beyla_file="$2"
    
    local obi_content=$(cat "$obi_file" | transform_obi_to_beyla | normalize_content)
    local beyla_content=$(cat "$beyla_file" | normalize_content)
    
    [[ "$obi_content" != "$beyla_content" ]]
}

# Sync a file from OBI to Beyla
sync_file() {
    local obi_file="$1"
    local beyla_file="$2"
    
    mkdir -p "$(dirname "$beyla_file")"
    cat "$obi_file" | transform_obi_to_beyla > "$beyla_file"
}

# Generic function to check drift in a set of files
# Usage: check_drift_in_files "label" find_command
check_drift_in_files() {
    local label="$1"
    shift
    local find_cmd="$*"
    
    local missing=0
    local drifted=0
    local missing_files=()
    local drifted_files=()
    
    while IFS= read -r obi_file; do
        [[ -f "$obi_file" ]] || continue
        
        local beyla_file=$(map_path "$obi_file")
        
        if [[ ! -f "$beyla_file" ]]; then
            missing_files+=("$obi_file")
            ((missing++)) || true
        elif files_have_drifted "$obi_file" "$beyla_file"; then
            drifted_files+=("$obi_file")
            ((drifted++)) || true
        fi
    done < <(eval "$find_cmd")
    
    # Sync if requested
    if [[ "$SYNC_MODE" == "true" ]]; then
        for obi_file in "${missing_files[@]}" "${drifted_files[@]}"; do
            sync_file "$obi_file" "$(map_path "$obi_file")"
        done
    fi
    
    # Compact output
    printf "%-25s %3d missing, %3d drifted" "$label:" "$missing" "$drifted"
    
    # Show file list in verbose mode or if small number
    local total=$((missing + drifted))
    if [[ "$VERBOSE" == "true" && $total -gt 0 ]]; then
        echo ""
        for f in "${missing_files[@]}"; do echo "  + ${f#$OBI_DIR/}"; done
        for f in "${drifted_files[@]}"; do echo "  ~ ${f#$OBI_DIR/}"; done
    elif [[ $total -gt 0 && $total -le 5 ]]; then
        echo ""
        for f in "${missing_files[@]}"; do echo "  + ${f#$OBI_DIR/}"; done
        for f in "${drifted_files[@]}"; do echo "  ~ ${f#$OBI_DIR/}"; done
    else
        echo ""
    fi
    
    TOTAL_DRIFT=$((TOTAL_DRIFT + missing + drifted))
}

# =============================================================================
# GO FUNCTION DRIFT (original functionality)
# =============================================================================

extract_function() {
    local func="$1" file="$2"
    sed -n "/^func $func(/,/^}/p" "$file"
}

find_function_file() {
    local func="$1" dir="$2"
    grep -l "^func $func(" "$dir"/*.go 2>/dev/null | head -1
}

find_common_functions() {
    local beyla_funcs=$(grep -rh "^func [a-z][a-zA-Z0-9_]*(" "$BEYLA_DIR"/*.go 2>/dev/null | \
        grep -E '\*testing\.(T|B)\b' | \
        sed 's/^func \([a-zA-Z0-9_]*\).*/\1/' | sort -u)
    
    local obi_funcs=$(grep -rh "^func [a-z][a-zA-Z0-9_]*(" "$OBI_DIR"/*.go 2>/dev/null | \
        grep -E '\*testing\.(T|B)\b' | \
        sed 's/^func \([a-zA-Z0-9_]*\).*/\1/' | sort -u)
    
    comm -12 <(echo "$beyla_funcs") <(echo "$obi_funcs")
}

is_using_shared_package() {
    local func="$1" file="$2"
    
    local alias=$(grep "go\.opentelemetry\.io/obi/pkg/test/integration" "$file" 2>/dev/null | \
        sed -n 's/^[[:space:]]*\([[:alpha:]][[:alnum:]]*\)[[:space:]]*"go\.opentelemetry\.io\/obi\/pkg\/test\/integration".*/\1/p' | head -1)
    
    if [[ -n "$alias" ]]; then
        extract_function "$func" "$file" | grep -qE "${alias}\.[A-Z][[:alpha:]]*\("
        return $?
    fi
    return 1
}

check_go_function_drift() {
    local func="$1"
    
    local beyla_file=$(find_function_file "$func" "$BEYLA_DIR")
    local obi_file=$(find_function_file "$func" "$OBI_DIR")
    
    [[ -z "$beyla_file" || -z "$obi_file" ]] && return 0
    is_using_shared_package "$func" "$beyla_file" && return 0
    
    local beyla_body=$(extract_function "$func" "$beyla_file" | \
        grep -v "Copyright The OpenTelemetry Authors" | \
        grep -v "SPDX-License-Identifier:" | \
        transform_beyla_to_obi)
    
    local obi_body=$(extract_function "$func" "$obi_file" | \
        grep -v "Copyright The OpenTelemetry Authors" | \
        grep -v "SPDX-License-Identifier:")
    
    if [[ "$beyla_body" != "$obi_body" ]]; then
        DRIFTED_FUNCS+=("$func:${beyla_file##*/}")
        if [[ "$SYNC_MODE" == "true" ]]; then
            local temp=$(mktemp)
            extract_function "$func" "$obi_file" | transform_obi_to_beyla > "$temp"
            go run "$(dirname "$0")/replace-function.go" -file "$beyla_file" -func "$func" -new "$temp"
            rm -f "$temp"
        fi
        return 1
    fi
    return 0
}

check_all_go_functions() {
    local total=0 drifted=0
    DRIFTED_FUNCS=()
    
    for func in $(find_common_functions); do
        ((total++)) || true
        check_go_function_drift "$func" || ((drifted++)) || true
    done
    
    printf "%-25s %3d drifted / %d total" "Go functions:" "$drifted" "$total"
    
    if [[ "$VERBOSE" == "true" && ${#DRIFTED_FUNCS[@]} -gt 0 ]]; then
        echo ""
        for f in "${DRIFTED_FUNCS[@]}"; do echo "  ~ $f"; done
    elif [[ ${#DRIFTED_FUNCS[@]} -gt 0 && ${#DRIFTED_FUNCS[@]} -le 5 ]]; then
        echo ""
        for f in "${DRIFTED_FUNCS[@]}"; do echo "  ~ $f"; done
    else
        echo ""
    fi
    
    TOTAL_DRIFT=$((TOTAL_DRIFT + drifted))
}

# =============================================================================
# HELP
# =============================================================================

show_help() {
    cat << 'EOF'
Usage: check-obi-drift.sh [OPTIONS]

Check for drift between Beyla and OBI test infrastructure, and optionally sync.

Compares:
  - Go test functions in internal/test/integration/*.go
  - Component files (Python, Dockerfiles, etc.) in components/
  - Config files in configs/
  - Docker-compose files

Options:
  --sync      Apply OBI changes to Beyla files
  --verbose   Show all drifted file names (default: only if ≤5)
  --help      Show this help

Examples:
  ./scripts/check-obi-drift.sh              # Quick summary
  ./scripts/check-obi-drift.sh --verbose    # List all drifted files
  ./scripts/check-obi-drift.sh --sync       # Sync changes

To see diff for a specific file:
  diff -u internal/test/integration/FILE .obi-src/internal/test/integration/FILE
EOF
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    local mode="CHECK"
    [[ "$SYNC_MODE" == "true" ]] && mode="SYNC"
    
    echo "OBI → Beyla drift $mode"
    echo "─────────────────────────────────────────────"
    
    # Go functions
    check_all_go_functions
    
    # Component files
    check_drift_in_files "Components" \
        "find '$OBI_DIR/components' -type f 2>/dev/null | while read -r f; do should_check_file \"\$f\" && echo \"\$f\"; done"
    
    # Config files
    check_drift_in_files "Configs" \
        "find '$OBI_DIR/configs' -maxdepth 1 -type f \\( -name '*.yml' -o -name '*.yaml' -o -name '*.json' \\) 2>/dev/null"
    
    # Docker-compose files
    check_drift_in_files "Docker-compose" \
        "find '$OBI_DIR' -maxdepth 1 -name 'docker-compose*.yml' -type f 2>/dev/null"
    
    echo "─────────────────────────────────────────────"
    
    if [[ $TOTAL_DRIFT -gt 0 ]]; then
        if [[ "$SYNC_MODE" == "true" ]]; then
            echo "✓ Synced $TOTAL_DRIFT items"
            echo "  Review: git diff internal/test/integration/"
        else
            echo "✗ $TOTAL_DRIFT items drifted"
            echo "  Run: $0 --sync"
            echo "  Or:  $0 --verbose  (to list all files)"
            exit 1
        fi
    else
        echo "✓ All in sync"
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sync) SYNC_MODE=true ;;
        --verbose|-v) VERBOSE=true ;;
        --help|-h) show_help; exit 0 ;;
        *) echo "Unknown option: $1"; show_help; exit 1 ;;
    esac
    shift
done

main
