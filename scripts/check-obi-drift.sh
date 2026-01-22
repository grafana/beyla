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

# Files with significant Beyla-specific content that shouldn't be synced
# These files have additions (like process metrics, discovery.survey, application_process) that don't exist in OBI
# Use OBI filenames since we check against OBI source files
SKIP_BEYLA_SPECIFIC_FILES=(
    'obi-config-java.yml'
    'obi-config-promscrape.yml'
    'obi-config-go-otel-grpc.yml'
    'obi-config-grpc-http2-mux.yml'
    'obi-config-http2.yml'
    # OBI has two wrapper scripts but Beyla only has beyla_wrapper.sh (manually maintained)
    'ebpf_instrument_wrapper_minimal.sh'
    'ebpf_instrument_wrapper.sh'
    # docker-compose.yml has significant Beyla-specific differences (pid namespace, env vars)
    # that cannot be automatically transformed from OBI
    'docker-compose.yml'
    # docker-compose files that use env var based discovery or have Beyla-specific config
    'docker-compose-client.yml'
    'docker-compose-php-fpm.yml'
    'docker-compose-php-fpm-sock.yml'
    # Java Kafka tests have different env var prefixes and otel collector versions
    'docker-compose-java-kafka.yml'
    'docker-compose-java-kafka-400.yml'
    'docker-compose-java-kafka-400-lb.yml'
    # Docker-compose files with Beyla-specific features (application_process, different values)
    'docker-compose-python.yml'
    'docker-compose-python-kafka.yml'
    'docker-compose-python-self.yml'
    'docker-compose-python-mongo.yml'
    'docker-compose-python-mysql.yml'
    'docker-compose-python-postgresql.yml'
    'docker-compose-python-redis.yml'
    'docker-compose-nodejs-dist.yml'
    'docker-compose-nodemultiproc.yml'
    'docker-compose-discovery.yml'
    'docker-compose-error-test.yml'
    'docker-compose-sampler.yml'
    'docker-compose-1.17.yml'
    # obi-config.yml has minor differences (otel_sdk_log_level, line ordering) - keep Beyla version
    'obi-config.yml'
    # Multiexec config files have discovery sections with regex patterns that differ between OBI and Beyla
    'obi-config-multiexec.yml'
    'obi-config-multiexec-host.yml'
)

# Beyla-specific component directories that should NOT be synced from OBI
# These are test components unique to Beyla that don't exist in OBI or have different requirements
SKIP_BEYLA_SPECIFIC_COMPONENTS=(
    'testserver_1.17'  # Beyla-specific test for oldest supported Go version (uses go 1.17)
)

# Beyla-specific integration test files that should NOT be synced from OBI
# These files either don't exist in OBI or have Beyla-specific test functions added
SKIP_BEYLA_SPECIFIC_TEST_FILES=(
    # K8s tests that are Beyla-only (don't exist in OBI)
    'connection_spans_test.go'           # TestConnectionSpans
    'k8s_daemonset_y_metrics_test.go'    # TestSurveyMetrics
    'k8s_daemonset_z_metrics_test.go'    # TestProcessMetrics
    'k8s_process_notraces_test.go'       # TestProcessMetrics_NoTraces
    # Top-level integration tests for Beyla-specific features
    'process_test.go'                    # Process metrics tests
    # K8s tests that exist in OBI but have Beyla-specific functions added
    'k8s_prom_test.go'                   # +TestPrometheus_ProcessMetrics, +TestPrometheus_SurveyMetrics
    'k8s_otel_metrics_test.go'           # +TestOTEL_ProcessMetrics
    'k8s_informer_cache_main_test.go'    # +TestInformersCache_ProcessMetrics
)

# Beyla-specific features that should be preserved if they exist in current Beyla files
# These are features that don't exist in OBI but may have been manually added to Beyla test files
BEYLA_PRESERVE_FEATURES=(
    'application_process'
)

# OBI -> Beyla text transformations (applied via sed)
# Format: "pattern|replacement" - order matters, more specific patterns first
# Note: BEYLA_OTEL_* and BEYLA_* are both valid (the OTEL_ is optional per config_obi.go)
# We use the shorter BEYLA_* form to match existing Beyla convention
TRANSFORMATIONS=(
    # OBI uses EXECUTABLE_PATH, Beyla uses EXECUTABLE_NAME (must be before generic OTEL_EBPF_ transform)
    'OTEL_EBPF_EXECUTABLE_PATH|BEYLA_EXECUTABLE_NAME'
    # Shell variable references also need to be transformed (e.g., ${JAVA_EXECUTABLE_PATH} -> ${JAVA_EXECUTABLE_NAME})
    'JAVA_EXECUTABLE_PATH|JAVA_EXECUTABLE_NAME'
    # These env vars keep OTEL_ part: OTEL_EBPF_X -> BEYLA_OTEL_X (to match main's convention)
    'OTEL_EBPF_TRACES_INSTRUMENTATIONS|BEYLA_OTEL_TRACES_INSTRUMENTATIONS'
    'OTEL_EBPF_METRICS_INSTRUMENTATIONS|BEYLA_OTEL_METRICS_INSTRUMENTATIONS'
    'OTEL_EBPF_METRICS_FEATURES|BEYLA_OTEL_METRICS_FEATURES'
    'OTEL_EBPF_|BEYLA_'
    'otel-ebpf|beyla'
    'otel_ebpf|beyla'
    # Attribute values should NOT have /v2 suffix (matched first, more specific)
    # Go struct format: Value: "..."
    'Value: "go.opentelemetry.io/obi"|Value: "github.com/grafana/beyla"'
    # JSON format: "value":"..." (for Jaeger test fixtures etc)
    '"value":"go.opentelemetry.io/obi"|"value":"github.com/grafana/beyla"'
    # Go import paths need /v2 suffix
    'go\.opentelemetry\.io/obi|github.com/grafana/beyla/v2'
    'obi-k8s-test-cluster|beyla-k8s-test-cluster'
    # K8s test Dockerfile variable names
    'DockerfileOBI|DockerfileBeyla'
    # Prometheus job names and scrape targets (obi-* -> beyla-*)
    'obi-network-flows|beyla-network-flows'
    'obi-testserver|beyla-testserver'
    'obi-pinger|beyla-pinger'
    'obi-netolly|beyla-netolly'
    'obi-promscrape|beyla-promscrape'
    'obi-collector|beyla-collector'
    # K8s manifest file references
    'obi-daemonset|beyla-daemonset'
    'obi-netolly|beyla-netolly'
    'obi-all-processes|beyla-all-processes'
    'obi-external-informer|beyla-external-informer'
    # Attribute names
    'obi\.ip|beyla.ip'
    # Config file naming (handles obi-config-*.yml and obi-config.yml and obi-config${VAR})
    'obi-config|instrumenter-config'
    'obi_|beyla_'
    # Volume paths and hostnames
    '/var/run/obi|/var/run/beyla'
    'HOSTNAME: "obi"|HOSTNAME: "beyla"'
    'hatest-obi|hatest-autoinstrumenter'
    # Image names with language prefixes (e.g., hatest-javaobi -> hatest-javaautoinstrumenter)
    'hatest-javaobi|hatest-javaautoinstrumenter'
    # SDK/service name (but NOT in GitHub URLs - those are preserved)
    'service_name="opentelemetry-ebpf-instrumentation"|service_name="beyla"'
    '"opentelemetry-ebpf-instrumentation"|"beyla"'
    # Dockerfile-specific: OBI uses bpf/, Beyla uses vendor/
    'COPY bpf/ bpf/|COPY vendor/ vendor/'
    # Wrapper script naming: OBI uses ebpf_instrument_wrapper*, Beyla uses beyla_wrapper*
    'ebpf_instrument_wrapper_minimal.sh|beyla_wrapper.sh'
    'ebpf_instrument_wrapper.sh|beyla_wrapper.sh'
    # Binary name in Dockerfile COPY commands
    '/src/bin/ebpf-instrument|/src/bin/beyla'
    '/ebpf-instrument|/beyla'
    # Binary path in entrypoint/command (e.g. - /ebpf-instrument -> - /beyla)
    '- /ebpf-instrument|- /beyla'
    'ebpf-instrument/Dockerfile|beyla/Dockerfile'
    'components/ebpf-instrument|components/beyla'
    'ebpf-instrument:|autoinstrumenter:'
    'service:ebpf-instrument|service:autoinstrumenter'
    'image: hatest-ebpf-instrument|image: hatest-autoinstrumenter'
    'obi:|autoinstrumenter:'
    'service:obi|service:autoinstrumenter'
    '// OBI |// Beyla '
    '# OBI |# Beyla '
    # Note: Copyright headers are stripped by normalize_content() instead of sed
    # Note: Go import path comments are stripped by transform patterns below
)

# Reverse transformations for comparison (Beyla -> OBI)
# Handles both BEYLA_OTEL_* and BEYLA_* forms
REVERSE_TRANSFORMATIONS=(
    # Beyla uses EXECUTABLE_NAME, OBI uses EXECUTABLE_PATH (must be before generic transforms)
    'BEYLA_EXECUTABLE_NAME|OTEL_EBPF_EXECUTABLE_PATH'
    # Shell variable references also need to be reversed
    'JAVA_EXECUTABLE_NAME|JAVA_EXECUTABLE_PATH'
    # These env vars have OTEL_ in Beyla: BEYLA_OTEL_X -> OTEL_EBPF_X (must be before generic transform)
    'BEYLA_OTEL_TRACES_INSTRUMENTATIONS|OTEL_EBPF_TRACES_INSTRUMENTATIONS'
    'BEYLA_OTEL_METRICS_INSTRUMENTATIONS|OTEL_EBPF_METRICS_INSTRUMENTATIONS'
    'BEYLA_OTEL_METRICS_FEATURES|OTEL_EBPF_METRICS_FEATURES'
    'BEYLA_OTEL_|OTEL_EBPF_'
    'BEYLA_|OTEL_EBPF_'
    # Attribute values (no /v2) - must be before import paths
    # Go struct format
    'Value: "github.com/grafana/beyla"|Value: "go.opentelemetry.io/obi"'
    # JSON format
    '"value":"github.com/grafana/beyla"|"value":"go.opentelemetry.io/obi"'
    # telemetry.sdk.name value (specific context to avoid over-matching)
    'Value: "beyla"|Value: "opentelemetry-ebpf-instrumentation"'
    # SDK/service name patterns
    'service_name="beyla"|service_name="opentelemetry-ebpf-instrumentation"'
    '"beyla"|"opentelemetry-ebpf-instrumentation"'
    # Go import paths (with /v2)
    'github\.com/grafana/beyla/v2|go.opentelemetry.io/obi'
    # Go import paths (without /v2, for any that slipped through)
    'github\.com/grafana/beyla|go.opentelemetry.io/obi'
    # Note: GitHub URLs are preserved as-is (not transformed)
    'beyla-k8s-test-cluster|obi-k8s-test-cluster'
    # K8s test Dockerfile variable names
    'DockerfileBeyla|DockerfileOBI'
    # Prometheus job names and scrape targets
    'beyla-network-flows|obi-network-flows'
    'beyla-testserver|obi-testserver'
    'beyla-pinger|obi-pinger'
    'beyla-netolly|obi-netolly'
    'beyla-promscrape|obi-promscrape'
    'beyla-collector|obi-collector'
    # K8s manifest file references
    'beyla-daemonset|obi-daemonset'
    'beyla-all-processes|obi-all-processes'
    'beyla-external-informer|obi-external-informer'
    # Attribute names
    'beyla\.ip|obi.ip'
    'instrumenter-config|obi-config'
    # Binary path in entrypoint/command (only at start of entrypoint, not in volume paths like /var/run/beyla)
    '- /beyla|- /ebpf-instrument'
    # Dockerfile and component paths
    'beyla/Dockerfile|ebpf-instrument/Dockerfile'
    'components/beyla|components/ebpf-instrument'
    # Dockerfile-specific: Beyla uses vendor/, OBI uses bpf/
    'COPY vendor/ vendor/|COPY bpf/ bpf/'
    # Wrapper script naming
    'beyla_wrapper.sh|ebpf_instrument_wrapper_minimal.sh'
    # Binary paths in Dockerfiles
    '/src/bin/beyla|/src/bin/ebpf-instrument'
    '/beyla|/ebpf-instrument'
    'beyla_|obi_'
    # Volume paths and hostnames
    '/var/run/beyla|/var/run/obi'
    'HOSTNAME: "beyla"|HOSTNAME: "obi"'
    'hatest-javaautoinstrumenter|hatest-javaobi'
    'hatest-autoinstrumenter|hatest-obi'
    'image: hatest-autoinstrumenter|image: hatest-obi'
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

# Transform OBI content to Beyla conventions
transform_obi_to_beyla() {
    local result
    result=$(cat)
    # Apply OBI->Beyla transformations
    for t in "${TRANSFORMATIONS[@]}"; do
        local pattern="${t%%|*}"
        local replacement="${t#*|}"
        result=$(echo "$result" | sed "s|${pattern}|${replacement}|g")
    done
    echo "$result"
}

# Add preserved features back to content if they existed in original file
# Usage: echo "$content" | add_preserved_features "$original_file"
add_preserved_features() {
    local original_file="$1"
    local result
    result=$(cat)
    
    [[ ! -f "$original_file" ]] && { echo "$result"; return; }
    
    for feature in "${BEYLA_PRESERVE_FEATURES[@]}"; do
        # For each FEATURES line in original that has the feature, add it to corresponding line in result
        while IFS= read -r orig_line; do
            # Extract the env var name (e.g., BEYLA_PROMETHEUS_FEATURES or BEYLA_OTEL_METRICS_FEATURES)
            local env_var=$(echo "$orig_line" | grep -oE '[A-Z_]+FEATURES')
            [[ -z "$env_var" ]] && continue
            
            # Use the env var name as-is (we now preserve BEYLA_OTEL_* names)
            local normalized_env_var="$env_var"
            
            # Check if this line in original has the feature
            if echo "$orig_line" | grep -q "$feature"; then
                # Check if result already has the feature for this env var (use normalized name)
                if ! echo "$result" | grep "$normalized_env_var" | grep -q "$feature"; then
                    # Add feature: try after application_span* (including _otel suffix) first, then after application
                    if echo "$result" | grep "$normalized_env_var" | grep -q "application_span"; then
                        # Match application_span plus any suffix (_otel, _sizes, etc.) as complete feature name
                        result=$(echo "$result" | sed -E "s/(${normalized_env_var}.*application_span[a-z_]*)([\",])/\1,${feature}\2/")
                    else
                        result=$(echo "$result" | sed -E "s/(${normalized_env_var}.*\"application)([\",])/\1,${feature}\2/")
                    fi
                fi
            fi
        done < <(grep "FEATURES" "$original_file" 2>/dev/null || true)
    done
    
    # Preserve COPY vendor/ lines in Dockerfiles (Beyla uses vendor/, OBI doesn't always have it)
    if [[ "$original_file" == *Dockerfile* ]] && grep -q "^COPY vendor/ vendor/" "$original_file" 2>/dev/null; then
        # If original has COPY vendor/ but result doesn't, add it
        if ! echo "$result" | grep -q "^COPY vendor/ vendor/"; then
            # Try to add after COPY .git/, or after "# Copy the go manifests" comment
            if echo "$result" | grep -q "^COPY \.git\/"; then
                result=$(echo "$result" | sed '/^COPY \.git\/ \.git\//a\
COPY vendor/ vendor/')
            elif echo "$result" | grep -q "# Copy the go manifests"; then
                result=$(echo "$result" | sed '/# Copy the go manifests/a\
COPY vendor/ vendor/')
            fi
        fi
    fi
    
    # Preserve ENV CGO_ENABLED=1 ONLY in the main beyla/Dockerfile (not component Dockerfiles)
    # Component Dockerfiles (go_otel, go_otel_grpc, etc.) should NOT have CGO_ENABLED=1
    # because their vendored dependencies (golang.org/x/sys/unix) contain C files that
    # cause build failures when CGO is enabled: "C source files not allowed when not using cgo or SWIG"
    if [[ "$original_file" == *components/beyla/Dockerfile* ]] && grep -q "^ENV CGO_ENABLED=1" "$original_file" 2>/dev/null; then
        # If original has CGO_ENABLED=1 but result doesn't, add it
        if ! echo "$result" | grep -q "^ENV CGO_ENABLED=1"; then
            # Try to add after ENV GOARCH=, or after ARG TARGETARCH
            if echo "$result" | grep -q "^ENV GOARCH="; then
                result=$(echo "$result" | sed '/^ENV GOARCH=/a\
ENV CGO_ENABLED=1')
            elif echo "$result" | grep -q "^ARG TARGETARCH"; then
                result=$(echo "$result" | sed '/^ARG TARGETARCH/a\
ENV CGO_ENABLED=1')
            fi
        fi
    fi
    
    # Preserve discovery sections in YAML config files (Beyla-only feature, not in OBI)
    if [[ "$original_file" == *.yml ]] || [[ "$original_file" == *.yaml ]]; then
        # Extract discovery section from Beyla's original file if it exists
        # The discovery section starts with "^discovery:" and includes all indented lines until next top-level key
        local discovery_section=$(awk '/^discovery:/ {p=1} p {if (/^[a-zA-Z][^:]*:/ && !/^discovery:/ && !/^  / && !/^    / && !/^      / && !/^        /) exit; print}' "$original_file" 2>/dev/null)
        if [[ -n "$discovery_section" ]] && ! echo "$result" | grep -q "^discovery:"; then
            # Add discovery section at the beginning of the file (before other top-level keys)
            # Find the first non-comment, non-blank line that's a top-level key
            local first_key=$(echo "$result" | grep -E "^[a-zA-Z]" | head -1)
            if [[ -n "$first_key" ]]; then
                # Insert discovery section before the first top-level key
                # Use awk to insert before the first key line
                local tmp_file=$(mktemp)
                echo "$discovery_section" > "$tmp_file"
                echo "" >> "$tmp_file"  # Add blank line after discovery section
                local first_key_pattern="${first_key%%:*}"
                result=$(echo "$result" | awk -v key="$first_key_pattern" -v discovery_file="$tmp_file" '
                    /^[a-zA-Z]/ && $0 ~ "^" key ":" && !found {
                        while ((getline line < discovery_file) > 0) {
                            print line
                        }
                        close(discovery_file)
                        found = 1
                    }
                    { print }
                ')
                rm -f "$tmp_file"
            else
                # If no other keys, just prepend
                result=$(echo -e "${discovery_section}\n${result}")
            fi
        fi
    fi
    
    echo "$result"
}

# Transform Beyla content to OBI conventions (for comparison)
transform_beyla_to_obi() {
    local result
    result=$(cat)
    for t in "${REVERSE_TRANSFORMATIONS[@]}"; do
        local pattern="${t%%|*}"
        local replacement="${t#*|}"
        result=$(echo "$result" | sed "s|${pattern}|${replacement}|g")
    done
    echo "$result"
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
    
    # Skip Beyla-specific files (files with significant Beyla additions)
    for skip_file in "${SKIP_BEYLA_SPECIFIC_FILES[@]}"; do
        [[ "$basename" == "$skip_file" ]] && return 1
    done
    
    # Skip Beyla-specific component directories
    for skip_comp in "${SKIP_BEYLA_SPECIFIC_COMPONENTS[@]}"; do
        echo "$file" | grep -qE "/components/$skip_comp/" && return 1
    done
    
    # Skip Beyla-specific test files (tests that don't exist in OBI)
    for skip_test in "${SKIP_BEYLA_SPECIFIC_TEST_FILES[@]}"; do
        [[ "$basename" == "$skip_test" ]] && return 1
    done
    
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
    path="${path//obi-config/instrumenter-config}"
    
    # Transform wrapper script filenames (both OBI variants map to single Beyla wrapper)
    path="${path//ebpf_instrument_wrapper_minimal.sh/beyla_wrapper.sh}"
    path="${path//ebpf_instrument_wrapper.sh/beyla_wrapper.sh}"
    
    echo "$path"
}

# =============================================================================
# GENERIC DRIFT CHECKING
# =============================================================================

# Check if two files have drifted (after normalization)
files_have_drifted() {
    local obi_file="$1"
    local beyla_file="$2"
    
    # Compare expected Beyla content (transformed from OBI, with preserved features) with actual Beyla content
    # Use same pipeline as sync_file for consistency
    local expected_beyla=$(cat "$obi_file" | strip_obi_headers | transform_obi_to_beyla | add_preserved_features "$beyla_file" | normalize_content)
    local actual_beyla=$(cat "$beyla_file" | normalize_content)
    
    [[ "$expected_beyla" != "$actual_beyla" ]]
}

# Strip OBI copyright headers and import path comments (Beyla doesn't use them in test files)
strip_obi_headers() {
    # Use || true to handle empty files (grep returns 1 when no matches)
    { grep -v "^// Copyright The OpenTelemetry Authors" || true; } | \
    { grep -v "^// SPDX-License-Identifier:" || true; } | \
    { grep -v "^# Copyright The OpenTelemetry Authors" || true; } | \
    { grep -v "^# SPDX-License-Identifier:" || true; } | \
    sed 's| // import "go\.opentelemetry\.io/obi[^"]*"||g' | \
    awk 'NF {p=1} p' | \
    cat -s
}

# Sync a file from OBI to Beyla
sync_file() {
    local obi_file="$1"
    local beyla_file="$2"
    
    mkdir -p "$(dirname "$beyla_file")"
    # Transform OBI to Beyla, strip copyrights/import comments, preserve Beyla-specific features
    cat "$obi_file" | strip_obi_headers | transform_obi_to_beyla | add_preserved_features "$beyla_file" > "${beyla_file}.tmp"
    mv "${beyla_file}.tmp" "$beyla_file"
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
        
        # Skip Beyla-specific files
        local basename="${obi_file##*/}"
        local skip=false
        for skip_file in "${SKIP_BEYLA_SPECIFIC_FILES[@]}"; do
            [[ "$basename" == "$skip_file" ]] && skip=true && break
        done
        [[ "$skip" == "true" ]] && continue
        
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
