#!/usr/bin/env bash
# Generate OBI integration tests from .obi-src submodule
#
# This script copies and transforms OBI test files to run within the Beyla project.
# Only files that require transformation are copied - standalone components (Dockerfiles,
# Python apps, etc.) are referenced in place via modified docker-compose paths.
#
# Usage:
#   ./scripts/generate-obi-tests.sh           # Generate OBI tests
#   ./scripts/generate-obi-tests.sh --clean   # Remove generated directory

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

OBI_SRC=".obi-src/internal/test/integration"
OBI_DEST="internal/obi/test/integration"

# OBI module path → Beyla module path
OBI_MODULE="go.opentelemetry.io/obi"
BEYLA_MODULE="github.com/grafana/beyla/v3"

# OBI Dockerfile → Beyla Dockerfile (for the instrumentation binary)
OBI_DOCKERFILE="internal/test/integration/components/ebpf-instrument/Dockerfile"
BEYLA_DOCKERFILE="internal/test/integration/components/beyla/Dockerfile"

# Go sub-packages are discovered automatically — see discover_go_packages().

# ---- Behavioral transforms: OBI → Beyla (applied to Go + YAML files) --------
# These ensure the generated tests validate Beyla-specific behavior:
#   - env var interface (BEYLA_* instead of OTEL_EBPF_*)
#   - metric name prefixes (beyla_ instead of obi_)
#   - trace/metric attribute names (beyla.* instead of obi.*)
#   - telemetry SDK identity
#
# See pkg/beyla/config_obi.go OverrideOBIGlobalConfig() for the runtime equivalents.
#
# Format: "obi_pattern|beyla_replacement" — order matters, specific before generic.
BEHAVIORAL_TRANSFORMS=(
    # --- Env var renames (input config interface) ---
    'OTEL_EBPF_EXECUTABLE_PATH|BEYLA_EXECUTABLE_NAME'
    'JAVA_EXECUTABLE_PATH|JAVA_EXECUTABLE_NAME'
    # Env vars that retain OTEL_ infix: OTEL_EBPF_X → BEYLA_OTEL_X
    'OTEL_EBPF_TRACES_INSTRUMENTATIONS|BEYLA_OTEL_TRACES_INSTRUMENTATIONS'
    'OTEL_EBPF_METRICS_INSTRUMENTATIONS|BEYLA_OTEL_METRICS_INSTRUMENTATIONS'
    'OTEL_EBPF_METRICS_FEATURES|BEYLA_OTEL_METRICS_FEATURES'
    'OTEL_EBPF_METRIC_FEATURES|BEYLA_OTEL_METRIC_FEATURES'
    'OTEL_EBPF_METRICS_TTL|BEYLA_OTEL_METRICS_TTL'
    # Generic env var prefix (must be after specific OTEL_EBPF_ rules above)
    'OTEL_EBPF_|BEYLA_'

    # --- Metric name prefixes (exported output) ---
    'obi_|beyla_'

    # --- Attribute names (exported output) ---
    'obi\.ip|beyla.ip'
    'obi\.network\.flow|beyla.network.flow'
    'obi\.network\.inter\.zone|beyla.network.inter.zone'

    # --- Telemetry SDK/scope identity ---
    'Value: "go\.opentelemetry\.io/obi"|Value: "github.com/grafana/beyla"'
    '"value":"go\.opentelemetry\.io/obi"|"value":"github.com/grafana/beyla"'
    'opentelemetry-ebpf-instrumentation|beyla'
)

# =============================================================================
# FUNCTIONS
# =============================================================================

# Portable sed -i (works on both macOS and Linux)
sed_i() {
    if [[ "$(uname)" == "Darwin" ]]; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

# Discover Go sub-packages imported by test files under OBI_SRC.
# These are the packages that must be copied (they can't be referenced in place
# because Go import paths are rewritten to the Beyla module).
discover_go_packages() {
    grep -roh "\"${OBI_MODULE}/internal/test/integration/[^\"]*\"" "$OBI_SRC" | \
        sed "s|\"${OBI_MODULE}/internal/test/integration/||;s|\"||" | \
        sort -u
}

# Apply an array of "pattern|replacement" transforms to a file using sed.
apply_transforms() {
    local file="$1"
    shift
    local transforms=("$@")
    for rule in "${transforms[@]}"; do
        local pattern="${rule%%|*}"
        local replacement="${rule#*|}"
        sed_i -e "s|${pattern}|${replacement}|g" "$file"
    done
}

clean() {
    echo "Cleaning generated OBI tests..."
    rm -rf "$OBI_DEST"
    echo "Done."
}

generate() {
    echo "Generating OBI tests from $OBI_SRC..."

    # Ensure source exists
    if [[ ! -d "$OBI_SRC" ]]; then
        echo "ERROR: OBI source not found at $OBI_SRC"
        echo "Make sure submodules are initialized: git submodule update --init"
        exit 1
    fi

    # -----------------------------------------------------------------
    # 1. Copy files
    # -----------------------------------------------------------------
    rm -rf "$OBI_DEST"
    mkdir -p "$OBI_DEST"

    echo "  Copying files..."
    find "$OBI_SRC" -maxdepth 1 -name "*.go" -exec cp {} "$OBI_DEST/" \;
    find "$OBI_SRC" -maxdepth 1 -name "docker-compose*.yml" -exec cp {} "$OBI_DEST/" \;
    cp -r "$OBI_SRC/configs" "$OBI_DEST/"
    cp -r "$OBI_SRC/system" "$OBI_DEST/"
    cp -r "$OBI_SRC/k8s" "$OBI_DEST/"

    echo "  Discovering and copying Go sub-packages..."
    discover_go_packages | while read -r pkg; do
        if [[ -d "$OBI_SRC/$pkg" ]]; then
            mkdir -p "$OBI_DEST/$pkg"
            find "$OBI_SRC/$pkg" -maxdepth 1 -name "*.go" -exec cp {} "$OBI_DEST/$pkg/" \;
        fi
    done

    if [[ -d ".obi-src/internal/test/tools" ]]; then
        mkdir -p "internal/obi/test/tools"
        cp -r ".obi-src/internal/test/tools/"* "internal/obi/test/tools/"
        find "internal/obi/test/tools" -name "*.go" -type f | while read -r file; do
            sed_i -e "s|${OBI_MODULE}/internal/test/tools|${BEYLA_MODULE}/internal/obi/test/tools|g" "$file"
        done
    fi

    # -----------------------------------------------------------------
    # 2. Go import / path transforms
    # -----------------------------------------------------------------
    echo "  Transforming Go imports and paths..."
    find "$OBI_DEST" -name "*.go" -type f | while read -r file; do
        sed_i \
            -e "s|${OBI_MODULE}/internal/test/integration|${BEYLA_MODULE}/internal/obi/test/integration|g" \
            -e "s|${OBI_MODULE}/internal/test/tools|${BEYLA_MODULE}/internal/obi/test/tools|g" \
            -e "s|// import \"${OBI_MODULE}/internal/test/integration[^\"]*\"||g" \
            -e 's|"internal/test/integration/components/|".obi-src/internal/test/integration/components/|g' \
            -e 's|"internal/test/integration/configs"|".obi-src/internal/test/integration/configs"|g' \
            -e 's|"internal/test/integration/system/|".obi-src/internal/test/integration/system/|g' \
            "$file"
    done

    # Point the OBI image build (in dockerutil_test.go) at the Beyla Dockerfile.
    if [[ -f "$OBI_DEST/dockerutil_test.go" ]]; then
        sed_i -e "s|Dockerfile:   \".obi-src/${OBI_DOCKERFILE}\"|Dockerfile:   \"${BEYLA_DOCKERFILE}\"|g" \
            "$OBI_DEST/dockerutil_test.go"
    fi

    # Update docker/compose.go to reference the obi test directory.
    if [[ -f "$OBI_DEST/components/docker/compose.go" ]]; then
        sed_i -e 's|"internal", "test", "integration"|"internal", "obi", "test", "integration"|g' \
            "$OBI_DEST/components/docker/compose.go"
    fi

    # -----------------------------------------------------------------
    # 3. Docker-compose path depth correction
    #    OBI compose files lived 3 levels below OBI root (internal/test/integration/).
    #    In Beyla they're 4 levels below Beyla root (internal/obi/test/integration/).
    #    All ../../.. references need an extra ../ level.
    # -----------------------------------------------------------------
    echo "  Adjusting docker-compose relative paths..."
    find "$OBI_DEST" -maxdepth 1 -name "docker-compose*.yml" | while read -r file; do
        # Build contexts → .obi-src (slash-suffixed first, then bare end-of-line)
        sed_i -e 's|context: \.\./\.\./\.\./|context: ../../../../.obi-src/|g' "$file"
        sed_i -e 's|context: \.\./\.\./\.\.$|context: ../../../../.obi-src|' "$file"
        # Volume mounts
        sed_i -e 's|\.\./\.\./\.\./testoutput|../../../../testoutput|g' "$file"
        sed_i -e 's|\.\./\.\./\.\./internal/|../../../../.obi-src/internal/|g' "$file"

        # Swap the OBI Dockerfile for the Beyla Dockerfile and point its
        # build context at the Beyla repo root instead of .obi-src.
        sed_i -e "s|dockerfile: \\./${OBI_DOCKERFILE}|dockerfile: ${BEYLA_DOCKERFILE}|" "$file"
        sed_i -e "s|dockerfile: ${OBI_DOCKERFILE}|dockerfile: ${BEYLA_DOCKERFILE}|" "$file"
        awk '{
            if (prev ~ /context:.*\.obi-src/ && $0 ~ /components\/beyla\/Dockerfile/) {
                sub(/\.\.\/\.\.\/\.\.\/\.\.\/\.obi-src/, "../../../..", prev)
            }
            if (NR > 1) print prev
            prev = $0
        } END { print prev }' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
    done

    # K8s manifests referencing component Dockerfiles
    find "$OBI_DEST/k8s" -name "*.yml" 2>/dev/null | while read -r file; do
        sed_i -e 's|dockerfile: internal/test/integration/components/|dockerfile: .obi-src/internal/test/integration/components/|g' "$file"
    done 2>/dev/null || true

    # -----------------------------------------------------------------
    # 4. Behavioral transforms (OBI → Beyla)
    # -----------------------------------------------------------------
    echo "  Applying OBI → Beyla behavioral transforms..."
    find "$OBI_DEST" -type f \( -name "*.go" -o -name "*.yml" -o -name "*.yaml" \) | while read -r file; do
        apply_transforms "$file" "${BEHAVIORAL_TRANSFORMS[@]}"
    done

    # -----------------------------------------------------------------
    # 5. Cleanup & build-tag injection
    # -----------------------------------------------------------------
    echo "  Cleaning up headers and adding build tags..."
    find "$OBI_DEST" -name "*.go" -type f | while read -r file; do
        sed_i \
            -e '/^\/\/ Copyright The OpenTelemetry Authors/d' \
            -e '/^\/\/ SPDX-License-Identifier:/d' \
            "$file"
    done

    find "$OBI_DEST" -name "*_test.go" -type f | while read -r file; do
        if ! grep -q "^//go:build" "$file"; then
            { echo "//go:build integration"; echo ""; cat "$file"; } > "$file.tmp"
            mv "$file.tmp" "$file"
        fi
    done

    echo "Done. Generated OBI tests at $OBI_DEST"
    echo ""
    echo "To run OBI tests: make test-integration-obi"
}

# =============================================================================
# MAIN
# =============================================================================

case "${1:-}" in
    --clean|-c)
        clean
        ;;
    --help|-h)
        echo "Usage: $0 [--clean]"
        echo ""
        echo "Generate OBI integration tests from .obi-src submodule."
        echo ""
        echo "Options:"
        echo "  --clean   Remove generated directory"
        echo "  --help    Show this help"
        ;;
    *)
        generate
        ;;
esac
