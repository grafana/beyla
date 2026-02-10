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
OBI_DOCKERFILE="internal/test/integration/components/obi/Dockerfile"
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
    'OTEL_EBPF_BPF_OPEN_PORT|BEYLA_OPEN_PORT'
    # Env vars that retain OTEL_ infix: OTEL_EBPF_X → BEYLA_OTEL_X
    'OTEL_EBPF_TRACES_INSTRUMENTATIONS|BEYLA_OTEL_TRACES_INSTRUMENTATIONS'
    'OTEL_EBPF_METRICS_INSTRUMENTATIONS|BEYLA_OTEL_METRICS_INSTRUMENTATIONS'
    'OTEL_EBPF_METRICS_FEATURES|BEYLA_OTEL_METRICS_FEATURES'
    'OTEL_EBPF_METRIC_FEATURES|BEYLA_OTEL_METRIC_FEATURES'
    'OTEL_EBPF_METRICS_TTL|BEYLA_OTEL_METRICS_TTL'
    # Generic env var prefix (must be after specific OTEL_EBPF_ rules above)
    'OTEL_EBPF_|BEYLA_'

    # --- Identity values (where "obi" is a config value or assertion, not a name) ---
    'HOSTNAME: "obi"|HOSTNAME: "beyla"'
    'value: "obi"|value: "beyla"'
    '/var/run/obi|/var/run/beyla'
    '"source":[ ]*"obi"|"source": "beyla"'

    # --- Binary name (entrypoint overrides in compose files) ---
    '/obi|/beyla'

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

# ---- Code injections (line inserted after a matching line in Go files) --------
# For cases where a simple substitution isn't enough — e.g. overriding a value
# returned by a vendored function, or adding a statement after a specific call.
#
# Format: "sed_pattern|code_to_inject"
CODE_INJECTIONS=(
    # The vendored DefaultOBIConfig() returns MetricPrefix="obi", but the
    # Beyla binary exports internal metrics with the "beyla" prefix.
    'config := ti\.DefaultOBIConfig()|config.MetricPrefix = "beyla"'
    # Temporarily skip flaky traceparent extraction test
    '^func TestTraceparentExtraction|t.Skip("temporarily skipped: investigating http.route/url.path mismatch in Beyla")'
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

# Discover Go sub-packages imported by the test files we copy, including
# transitive imports. Starts from root-level and k8s test files, then
# iteratively resolves imports from discovered packages until stable.
discover_go_packages() {
    local import_pattern="\"${OBI_MODULE}/internal/test/integration/[^\"]*\""
    local extract="s|\"${OBI_MODULE}/internal/test/integration/||;s|\"||"
    local prev="" pkgs

    # Seed: direct imports from root-level Go files and k8s test files
    pkgs=$(
        {
            find "$OBI_SRC" -maxdepth 1 -name "*.go" -exec grep -oh "$import_pattern" {} +
            find "$OBI_SRC/k8s" -name "*.go" -exec grep -oh "$import_pattern" {} + 2>/dev/null
        } | sed "$extract" | sort -u
    )

    # Iterate: resolve transitive imports from discovered packages
    while [[ "$pkgs" != "$prev" ]]; do
        prev="$pkgs"
        pkgs=$(
            {
                echo "$prev"
                echo "$prev" | while read -r pkg; do
                    [[ -d "$OBI_SRC/$pkg" ]] && \
                        find "$OBI_SRC/$pkg" -maxdepth 1 -name "*.go" \
                            -exec grep -oh "$import_pattern" {} + 2>/dev/null
                done
            } | sed "$extract" | sort -u
        )
    done
    echo "$pkgs"
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

# Inject a line of code after each matching line in a file.
# Rules are "sed_pattern|code_to_inject"; only files containing the pattern
# are modified.
# Uses awk instead of sed for the injection because BSD sed (macOS) does not
# interpret \n in replacement strings.
apply_injections() {
    local file="$1"
    shift
    local rules=("$@")
    for rule in "${rules[@]}"; do
        local pattern="${rule%%|*}"
        local injection="${rule#*|}"
        if grep -q "${pattern}" "$file" 2>/dev/null; then
            awk -v pat="${pattern}" -v inj="${injection}" \
                '{print} $0 ~ pat {print "\t" inj}' "$file" > "$file.tmp" \
                && mv "$file.tmp" "$file"
        fi
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
    # 1b. Copy Beyla-specific extension tests
    #     These are Beyla-original tests (not from OBI upstream) that run
    #     alongside the generated OBI tests. They already use Beyla naming
    #     (BEYLA_* env vars, beyla_ metric prefix) so no behavioral
    #     transforms are needed — just a straight copy.
    # -----------------------------------------------------------------
    echo "  Copying Beyla extension tests..."
    BEYLA_EXT="internal/test/beyla_extensions"
    if [[ -d "$BEYLA_EXT" ]]; then
        find "$BEYLA_EXT" -maxdepth 1 -name "*.go" -exec cp {} "$OBI_DEST/" \;
        find "$BEYLA_EXT" -maxdepth 1 -name "docker-compose*.yml" -exec cp {} "$OBI_DEST/" \;
        # Source Go files use //go:build beyla_extension to prevent compilation
        # during lint (the linter only enables the 'integration' tag).
        # Replace with //go:build integration for the generated output.
        for file in "$OBI_DEST"/*.go; do
            sed_i 's|^//go:build beyla_extension$|//go:build integration|' "$file"
        done
        # Copy Beyla-specific config overrides (e.g. configs that add
        # application_process features for process-level metric tests).
        # These overlay on top of the OBI upstream configs already copied.
        if [[ -d "$BEYLA_EXT/configs" ]]; then
            cp "$BEYLA_EXT"/configs/*.yml "$OBI_DEST/configs/" 2>/dev/null || true
        fi
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

        # Redirect bare ./components/ and components/ paths to .obi-src.
        # These reference standalone app dirs that aren't copied to the
        # generated output (they're built via Docker from the OBI source).
        sed_i -e 's|\./components/|../../../../.obi-src/internal/test/integration/components/|g' "$file"
        sed_i -e 's|context: components/|context: ../../../../.obi-src/internal/test/integration/components/|g' "$file"

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
    find "$OBI_DEST" -name "*.go" -type f | while read -r file; do
        apply_injections "$file" "${CODE_INJECTIONS[@]}"
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
