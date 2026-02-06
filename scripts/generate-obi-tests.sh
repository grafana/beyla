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

# Go packages that must be copied (due to internal visibility rules)
GO_PACKAGES=(
    "components/docker"
    "components/jaeger"
    "components/promtest"
    "components/kube"
    "components/testserver/grpc/client"
    "components/testserver/grpc/routeguide"
    "components/testserver/grpc/server"
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
    
    # Clean destination
    rm -rf "$OBI_DEST"
    mkdir -p "$OBI_DEST"
    
    # Copy root-level Go files
    echo "  Copying root Go files..."
    find "$OBI_SRC" -maxdepth 1 -name "*.go" -exec cp {} "$OBI_DEST/" \;
    
    # Copy docker-compose files
    echo "  Copying docker-compose files..."
    find "$OBI_SRC" -maxdepth 1 -name "docker-compose*.yml" -exec cp {} "$OBI_DEST/" \;
    
    # Copy configs directory
    echo "  Copying configs..."
    cp -r "$OBI_SRC/configs" "$OBI_DEST/"
    
    # Copy system directory (test fixtures)
    echo "  Copying system fixtures..."
    cp -r "$OBI_SRC/system" "$OBI_DEST/"
    
    # Copy K8s test files and manifests
    echo "  Copying K8s tests..."
    cp -r "$OBI_SRC/k8s" "$OBI_DEST/"
    
    # Copy required Go packages
    echo "  Copying Go packages..."
    for pkg in "${GO_PACKAGES[@]}"; do
        if [[ -d "$OBI_SRC/$pkg" ]]; then
            mkdir -p "$OBI_DEST/$pkg"
            find "$OBI_SRC/$pkg" -maxdepth 1 -name "*.go" -exec cp {} "$OBI_DEST/$pkg/" \;
        fi
    done
    
    # Transform Go import paths and Dockerfile references in Go files
    echo "  Transforming Go imports..."
    find "$OBI_DEST" -name "*.go" -type f | while read -r file; do
        sed_i \
            -e 's|go\.opentelemetry\.io/obi/internal/test/integration|github.com/grafana/beyla/v3/internal/obi/test/integration|g' \
            -e 's|go\.opentelemetry\.io/obi/internal/test/tools|github.com/grafana/beyla/v3/internal/obi/test/tools|g' \
            -e 's|// import "go\.opentelemetry\.io/obi/internal/test/integration[^"]*"||g' \
            -e 's|"internal/test/integration/components/|".obi-src/internal/test/integration/components/|g' \
            "$file"
    done
    
    # Transform environment variable prefixes in YAML files
    echo "  Transforming env vars in configs..."
    find "$OBI_DEST" -type f \( -name "*.yml" -o -name "*.yaml" \) | while read -r file; do
        sed_i \
            -e 's|OTEL_EBPF_EXECUTABLE_PATH|BEYLA_EXECUTABLE_NAME|g' \
            -e 's|OTEL_EBPF_|BEYLA_|g' \
            "$file"
    done
    
    # Transform docker-compose Dockerfile paths to reference .obi-src
    # For non-OBI Dockerfiles: prefix path with .obi-src/ (context stays at repo root)
    # For ebpf-instrument: change context to .obi-src root (it needs bpf/, cmd/, pkg/)
    echo "  Transforming docker-compose Dockerfile paths..."
    find "$OBI_DEST" -maxdepth 1 -name "docker-compose*.yml" | while read -r file; do
        sed_i \
            -e 's|dockerfile: internal/test/integration/components/|dockerfile: .obi-src/internal/test/integration/components/|g' \
            -e 's|dockerfile: \./internal/test/integration/components/|dockerfile: .obi-src/internal/test/integration/components/|g' \
            "$file"
        # ebpf-instrument Dockerfile needs OBI's bpf/, cmd/, pkg/ dirs in its build context.
        # Change context from repo root to .obi-src and remove .obi-src/ prefix from Dockerfile path.
        sed_i \
            -e '/dockerfile:.*\.obi-src.*ebpf-instrument/{s|dockerfile: \.obi-src/|dockerfile: |;}' \
            "$file"
        # Adjust context line preceding ebpf-instrument dockerfile to point to .obi-src
        sed_i \
            -e '/ebpf-instrument/!{N;/\n.*ebpf-instrument/{s|context: \.\./\.\./\.\.|context: ../../../../.obi-src|;};P;D;}' \
            "$file"
    done
    
    # Transform docker-compose paths in K8s manifests (if any reference components)
    find "$OBI_DEST/k8s" -name "*.yml" 2>/dev/null | while read -r file; do
        sed_i \
            -e 's|dockerfile: internal/test/integration/components/|dockerfile: .obi-src/internal/test/integration/components/|g' \
            "$file"
    done 2>/dev/null || true
    
    # Update docker/compose.go to use OBI test directory
    if [[ -f "$OBI_DEST/components/docker/compose.go" ]]; then
        echo "  Updating docker/compose.go paths..."
        sed_i \
            -e 's|"internal", "test", "integration"|"internal", "obi", "test", "integration"|g' \
            "$OBI_DEST/components/docker/compose.go"
    fi
    
    # Copy tools directory if it exists and is needed
    if [[ -d ".obi-src/internal/test/tools" ]]; then
        echo "  Copying test tools..."
        mkdir -p "internal/obi/test/tools"
        cp -r ".obi-src/internal/test/tools/"* "internal/obi/test/tools/"
        # Transform imports in tools
        find "internal/obi/test/tools" -name "*.go" -type f | while read -r file; do
            sed_i \
                -e 's|go\.opentelemetry\.io/obi/internal/test/tools|github.com/grafana/beyla/v3/internal/obi/test/tools|g' \
                "$file"
        done
    fi
    
    # NOTE: Beyla-specific extension files (internal/test/beyla_extensions/) are NOT copied here.
    # They depend on Beyla's test infrastructure and run as a separate test target.
    # See: make integration-test-beyla
    
    # Remove OBI copyright headers (Beyla has its own)
    echo "  Cleaning up headers..."
    find "$OBI_DEST" -name "*.go" -type f | while read -r file; do
        sed_i \
            -e '/^\/\/ Copyright The OpenTelemetry Authors/d' \
            -e '/^\/\/ SPDX-License-Identifier:/d' \
            "$file"
    done
    
    # Add //go:build integration tag to test files that don't have it
    echo "  Adding build tags to test files..."
    find "$OBI_DEST" -name "*_test.go" -type f | while read -r file; do
        if ! grep -q "^//go:build" "$file"; then
            # Create temp file with build tag prepended
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
