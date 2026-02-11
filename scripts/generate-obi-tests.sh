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

OATS_SRC=".obi-src/internal/test/oats"
OATS_DEST="internal/obi/test/oats"

VM_SRC=".obi-src/internal/test/vm"
VM_DEST="internal/obi/test/vm"

# OBI module path → Beyla module path
OBI_MODULE="go.opentelemetry.io/obi"
BEYLA_MODULE="github.com/grafana/beyla/v3"

# OBI Dockerfile → Beyla Dockerfile (for the instrumentation binary)
OBI_DOCKERFILE="internal/test/integration/components/obi/Dockerfile"
BEYLA_DOCKERFILE="internal/test/beyla_extensions/components/beyla/Dockerfile"

# Go sub-packages are discovered automatically — see discover_go_packages().

# Parallel workers for file-wide transforms. Override with OBI_GEN_JOBS.
default_jobs() {
    if [[ -n "${OBI_GEN_JOBS:-}" ]]; then
        echo "$OBI_GEN_JOBS"
        return
    fi
    if command -v sysctl >/dev/null 2>&1; then
        sysctl -n hw.logicalcpu 2>/dev/null && return
    fi
    if command -v getconf >/dev/null 2>&1; then
        getconf _NPROCESSORS_ONLN 2>/dev/null && return
    fi
    echo 4
}

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
    '^/obi|/beyla'
    '\([^.a-zA-Z0-9/_-]\)/obi|\1/beyla'

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

    # --- K8s component paths ---
    'DockerfileOBI|DockerfileBeyla'
    'DockerfileK8sCache|DockerfileBeylaK8sCache'
    'internal/test/integration/components/beyla|internal/test/beyla_extensions/components/beyla'
    'internal/test/integration/components/beyla-k8s-cache|internal/test/beyla_extensions/components/beyla-k8s-cache'

    # --- K8s image tags ---
    '"obi:dev"|"beyla:dev"'
    '"obi-k8s-cache:dev"|"beyla-k8s-cache:dev"'
    'Tag: "obi:dev"|Tag: "beyla:dev"'
    # YAML manifests use unquoted image tags
    'image: obi:dev|image: beyla:dev'
    'image: obi-k8s-cache:dev|image: beyla-k8s-cache:dev'
    # Generated k8s manifests are nested one level deeper than upstream:
    # internal/obi/test/integration/k8s/manifests, so testoutput hostPath
    # needs one extra "../" to keep pointing at repo-root ./testoutput.
    '../../../../../testoutput|../../../../../../testoutput'
)

# ---- Code injections (line inserted after a matching line in Go files) --------
# For cases where a simple substitution isn't enough — e.g. overriding a value
# returned by a vendored function, or adding a statement after a specific call.
#
# Format: "sed_pattern|code_to_inject"
CODE_INJECTIONS=(
    # Path setup: OBI components live in .obi-src submodule (run early, before path-dependent transforms)
    'pathRoot   = tools.ProjectDir()|pathObiSrc  = path.Join(pathRoot, ".obi-src")'
    'Root            = tools.ProjectDir()|ObiRoot         = path.Join(Root, ".obi-src")'
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
    local sed_args=()
    for rule in "${transforms[@]}"; do
        local pattern="${rule%%|*}"
        local replacement="${rule#*|}"
        sed_args+=(-e "s|${pattern}|${replacement}|g")
    done
    sed_i "${sed_args[@]}" "$file"
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
        local awk_pattern="${pattern//\\/\\\\}"
        if grep -q "${pattern}" "$file" 2>/dev/null; then
            awk -v pat="${awk_pattern}" -v inj="${injection}" \
                '{print} $0 ~ pat {print "\t" inj}' "$file" > "$file.tmp" \
                && mv "$file.tmp" "$file"
        fi
    done
}

# Run a worker function against newline-delimited file paths from stdin using
# bounded parallelism in fixed-size batches (portable to bash 3.x).
run_parallel() {
    local jobs="$1"
    local worker="$2"
    shift 2
    local worker_args=("$@")
    local pids=()
    local file
    local running=0

    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        "$worker" "$file" "${worker_args[@]}" &
        pids+=($!)
        running=$((running + 1))

        if (( running >= jobs )); then
            local pid
            for pid in "${pids[@]}"; do
                wait "$pid"
            done
            pids=()
            running=0
        fi
    done

    local pid
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
}

clean() {
    echo "Cleaning generated OBI tests..."
    rm -rf "$OBI_DEST"
    rm -rf "$OATS_DEST"
    rm -rf "$VM_DEST"
    echo "Done."
}

apply_go_import_path_transforms() {
    local file="$1"
    sed_i \
        -e 's|^//go:build ignore$|//go:build integration|' \
        -e "s|${OBI_MODULE}/internal/test/integration|${BEYLA_MODULE}/internal/obi/test/integration|g" \
        -e "s|${OBI_MODULE}/internal/test/tools|${BEYLA_MODULE}/internal/obi/test/tools|g" \
        -e "s|${BEYLA_MODULE}/internal/test/integration|${BEYLA_MODULE}/internal/obi/test/integration|g" \
        -e "s|${BEYLA_MODULE}/internal/test/tools|${BEYLA_MODULE}/internal/obi/test/tools|g" \
        -e "s|// import \"${OBI_MODULE}/internal/test/integration[^\"]*\"||g" \
        -e 's|"internal/test/integration/components/|".obi-src/internal/test/integration/components/|g' \
        -e 's|"internal/test/integration/configs"|".obi-src/internal/test/integration/configs"|g' \
        -e 's|"internal/test/integration/system/|".obi-src/internal/test/integration/system/|g' \
        "$file"
}

determine_jobs() {
    local jobs
    jobs="$(default_jobs)"
    [[ "$jobs" =~ ^[0-9]+$ ]] || jobs=4
    if (( jobs < 1 )); then
        jobs=1
    fi
    echo "$jobs"
}

ensure_source_exists() {
    # Ensure source exists
    if [[ ! -d "$OBI_SRC" ]]; then
        echo "ERROR: OBI source not found at $OBI_SRC"
        echo "Make sure submodules are initialized: git submodule update --init"
        exit 1
    fi
}

prepare_destination() {
    rm -rf "$OBI_DEST"
    mkdir -p "$OBI_DEST"
}

copy_upstream_files() {
    echo "  Copying files..."
    find "$OBI_SRC" -maxdepth 1 -name "*.go" -exec cp {} "$OBI_DEST/" \;
    find "$OBI_SRC" -maxdepth 1 -name "docker-compose*.yml" -exec cp {} "$OBI_DEST/" \;
    cp -r "$OBI_SRC/configs" "$OBI_DEST/"
    cp -r "$OBI_SRC/system" "$OBI_DEST/"
    cp -r "$OBI_SRC/k8s" "$OBI_DEST/"
}

copy_beyla_manifests() {
    # Copy Beyla-specific manifests (no OBI counterpart) into generated manifests dir
    local beyla_manifests_src="internal/test/beyla_extensions/k8s/manifests"
    local beyla_manifests="$OBI_DEST/k8s/manifests"
    for f in 06-beyla-all-processes.yml 06-beyla-daemonset-topology-extern.yml; do
        if [[ -f "$beyla_manifests_src/$f" ]]; then
            cp "$beyla_manifests_src/$f" "$beyla_manifests/"
        fi
    done 2>/dev/null || true
}

copy_discovered_go_subpackages() {
    echo "  Discovering and copying Go sub-packages..."
    discover_go_packages | while read -r pkg; do
        if [[ -d "$OBI_SRC/$pkg" ]]; then
            mkdir -p "$OBI_DEST/$pkg"
            find "$OBI_SRC/$pkg" -maxdepth 1 -name "*.go" -exec cp {} "$OBI_DEST/$pkg/" \;
        fi
    done
}

copy_test_tools() {
    if [[ -d ".obi-src/internal/test/tools" ]]; then
        mkdir -p "internal/obi/test/tools"
        cp -r ".obi-src/internal/test/tools/"* "internal/obi/test/tools/"
        find "internal/obi/test/tools" -name "*.go" -type f | while read -r file; do
            sed_i -e "s|${OBI_MODULE}/internal/test/tools|${BEYLA_MODULE}/internal/obi/test/tools|g" "$file"
        done
    fi
}

copy_beyla_extensions() {
    echo "  Copying Beyla extension tests..."
    local beyla_ext="internal/test/beyla_extensions"
    if [[ -d "$beyla_ext" ]]; then
        find "$beyla_ext" -maxdepth 1 -name "*.go" -exec cp {} "$OBI_DEST/" \;
        find "$beyla_ext" -maxdepth 1 -name "docker-compose*.yml" -exec cp {} "$OBI_DEST/" \;
        # Source Go files use //go:build ignore to prevent compilation during
        # vendor and lint. Replace with //go:build integration for the generated output.
        for file in "$OBI_DEST"/*.go; do
            sed_i 's|^//go:build ignore$|//go:build integration|' "$file"
        done
        # Copy Beyla-specific config overrides (e.g. configs that add
        # application_process features for process-level metric tests).
        # These overlay on top of the OBI upstream configs already copied.
        if [[ -d "$beyla_ext/configs" ]]; then
            cp "$beyla_ext"/configs/*.yml "$OBI_DEST/configs/" 2>/dev/null || true
        fi
        # Copy Beyla-specific k8s tests: process_notraces, connection_spans,
        # daemonset y/z metrics. These merge into the generated k8s output.
        if [[ -d "$beyla_ext/k8s" ]]; then
            echo "  Copying Beyla extension k8s tests..."
            for dir in "$beyla_ext/k8s"/*/; do
                [[ -d "$dir" ]] || continue
                dirname=$(basename "$dir")
                mkdir -p "$OBI_DEST/k8s/$dirname"
                find "$dir" -maxdepth 1 -name "*.go" -exec cp {} "$OBI_DEST/k8s/$dirname/" \;
            done
        fi
    fi
}

transform_go_imports_and_paths() {
    local jobs="$1"
    echo "  Transforming Go imports and paths..."
    # Run code injections first (pathObiSrc, ObiRoot) so later blocks can reference them
    find "$OBI_DEST" -name "*.go" -type f | run_parallel "$jobs" apply_injections "${CODE_INJECTIONS[@]}"
    find "$OBI_DEST" -name "*.go" -type f | run_parallel "$jobs" apply_go_import_path_transforms

    # Point the OBI image build (in dockerutil_test.go) at the Beyla Dockerfile.
    if [[ -f "$OBI_DEST/dockerutil_test.go" ]]; then
        sed_i -e "s|Dockerfile:   \".obi-src/${OBI_DOCKERFILE}\"|Dockerfile:   \"${BEYLA_DOCKERFILE}\"|g" \
            "$OBI_DEST/dockerutil_test.go"
    fi

    # go_otel BuildImage: use .obi-src as context (go_otel Dockerfile expects
    # internal/test/integration/components/go_otel/ relative to context).
    if [[ -f "$OBI_DEST/http_go_otel_test.go" ]]; then
        sed_i -e 's|ContextDir:   pathRoot,|ContextDir:   pathObiSrc,|' \
            -e 's|Dockerfile:   "\.obi-src/internal/test/integration/components/go_otel/Dockerfile"|Dockerfile:   "internal/test/integration/components/go_otel/Dockerfile"|' \
            "$OBI_DEST/http_go_otel_test.go"
    fi

    # Component file paths: testserver, rusttestserver etc. live in .obi-src.
    find "$OBI_DEST" -name "*.go" -type f | run_parallel "$jobs" apply_component_path_transform

    # Update docker/compose.go to reference the obi test directory.
    if [[ -f "$OBI_DEST/components/docker/compose.go" ]]; then
        sed_i -e 's|"internal", "test", "integration"|"internal", "obi", "test", "integration"|g' \
            "$OBI_DEST/components/docker/compose.go"
    fi
}

apply_component_consolidation() {
    if [[ -f "$OBI_DEST/k8s/common/testpath/testpath.go" ]]; then
        sed_i -e 's|Components      = path.Join(IntegrationTest, "components")|Components      = path.Join(Root, ".obi-src", "internal", "test", "integration", "components")|' \
            "$OBI_DEST/k8s/common/testpath/testpath.go"
        # Manifests sourced from OBI (internal/obi) — content transformed on the fly during generate
        sed_i -e 's|Manifests       = path.Join(IntegrationTest, "k8s", "manifests")|Manifests       = path.Join(Root, "internal", "obi", "test", "integration", "k8s", "manifests")|' \
            "$OBI_DEST/k8s/common/testpath/testpath.go"
    fi
    # k8s_common: path replacements only; variable names (DockerfileOBI→DockerfileBeyla)
    # are handled by BEHAVIORAL_TRANSFORMS in step 4.
    if [[ -f "$OBI_DEST/k8s/common/k8s_common.go" ]]; then
        sed_i -e 's|path.Join(testpath.Components, "obi", "Dockerfile")|path.Join(testpath.Root, "internal", "test", "beyla_extensions", "components", "beyla", "Dockerfile")|' \
            -e 's|path.Join(testpath.Components, "ebpf-instrument-k8s-cache", "Dockerfile")|path.Join(testpath.Root, "internal", "test", "beyla_extensions", "components", "beyla-k8s-cache", "Dockerfile")|' \
            "$OBI_DEST/k8s/common/k8s_common.go"
    fi
}

adjust_docker_compose_paths() {
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
        # Beyla Dockerfile paths (beyla_extensions) handled by BEHAVIORAL_TRANSFORMS in step 4.
        # When context points to .obi-src but dockerfile is Beyla (in beyla_extensions),
        # use repo root as context instead.
        awk '{
            if (prev ~ /context:.*\.obi-src/ && $0 ~ /beyla_extensions\/components\/(beyla|beyla-k8s-cache)\/Dockerfile/) {
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
}

ensure_multiexec_local_image_reuse() {
    # docker compose up --quiet-pull attempts to pull image-only services. The
    # multiexec suites intentionally reuse the image built by testserver.
    for file in "$OBI_DEST/docker-compose-multiexec.yml" "$OBI_DEST/docker-compose-multiexec-host.yml"; do
        [[ -f "$file" ]] || continue
        awk '
            /^  testserver-unused:$/ { in_unused=1 }
            in_unused && /^    image: hatest-testserver$/ {
                print
                print "    pull_policy: never"
                next
            }
            in_unused && /^  [a-zA-Z0-9_-]+:$/ && $0 !~ /^  testserver-unused:$/ { in_unused=0 }
            { print }
        ' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
    done
}

split_docker_build_contexts() {
    # Split docker.Build: OBI components (testserver, pythontestserver, etc.) need
    # .obi-src as build context; Beyla needs repo root. Tests with both get two Build calls.
    echo "  Splitting docker.Build for OBI vs Beyla context..."
    local script_dir
    script_dir="$(cd "$(dirname "$0")" && pwd)"
    find "$OBI_DEST/k8s" -name "*_test.go" -type f | while read -r file; do
        grep -q 'docker.Build.*tools.ProjectDir' "$file" || continue
        python3 "$script_dir/split-docker-build.py" "$file" || true
    done 2>/dev/null || true
}

ensure_daemonset_process_metrics_enabled() {
    # Daemonset y/z extension tests assert process_* and survey_info.
    # The generated 06-obi-daemonset manifest must enable application_process.
    local file="$OBI_DEST/k8s/manifests/06-obi-daemonset.yml"
    [[ -f "$file" ]] || return 0
    sed_i -e '/name: BEYLA_OTEL_METRICS_FEATURES/{n;s|value: "application"|value: "application,application_process"|;}' "$file"
    # TestSurveyMetrics expects survey_info; it is only emitted when discovery.survey is set.
    if ! grep -q 'survey:' "$file"; then
        awk '/exclude_instrument:/ {
            print "      survey:"
            print "        - k8s_deployment_name: \"otherinstance\""
        }
        { print }' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
    fi
}

ensure_otherinstance_has_service_version() {
    # Daemonset y/z tests expect service_version "3.2.1" for otherinstance.
    # Add resource.opentelemetry.io/service.version annotation so metrics get decorated.
    # (testserver already has it; we add to otherinstance which has to-be-ignored-in-favor-of-env-var)
    local file="$OBI_DEST/k8s/manifests/05-uninstrumented-service.yml"
    [[ -f "$file" ]] || return 0
    if ! grep -A1 "to-be-ignored-in-favor-of-env-var" "$file" | grep -q "resource.opentelemetry.io/service.version"; then
        awk "/to-be-ignored-in-favor-of-env-var/ { print; print \"        resource.opentelemetry.io/service.version: '3.2.1'\"; next } 1" "$file" > "$file.tmp" && mv "$file.tmp" "$file"
    fi
}

apply_behavioral_transforms() {
    local jobs="$1"
    echo "  Applying OBI → Beyla behavioral transforms..."
    find "$OBI_DEST" -type f \( -name "*.go" -o -name "*.yml" -o -name "*.yaml" \) | run_parallel "$jobs" apply_transforms "${BEHAVIORAL_TRANSFORMS[@]}"
}

cleanup_and_inject_build_tags() {
    local jobs="$1"
    echo "  Cleaning up headers and adding build tags..."
    find "$OBI_DEST" -name "*.go" -type f | run_parallel "$jobs" strip_headers

    find "$OBI_DEST" -name "*_test.go" -type f | while read -r file; do
        if ! grep -q "^//go:build" "$file"; then
            { echo "//go:build integration"; echo ""; cat "$file"; } > "$file.tmp"
            mv "$file.tmp" "$file"
        fi
    done
}

# =============================================================================
# OATs FUNCTIONS
# =============================================================================

copy_oats() {
    echo "  Copying OATs..."
    if [[ -d "$OATS_SRC" ]]; then
        rm -rf "$OATS_DEST"
        mkdir -p "$OATS_DEST"
        cp -r "$OATS_SRC"/* "$OATS_DEST/"
    fi
}

adjust_oats_compose_paths() {
    echo "  Adjusting OATs docker-compose paths..."
    find "$OATS_DEST" -name "docker-compose*.yml" | while read -r file; do
        # Component build contexts: OATs reference OBI components via relative path
        # ../../integration/components/ → absolute path via .obi-src
        sed_i -e 's|context: \.\./\.\./integration/components/|context: ../../../../../.obi-src/internal/test/integration/components/|g' "$file"

        # Volume mount paths: some compose files mount files from OBI components
        # (e.g. init.sql, certs). These also use ../../integration/components/
        sed_i -e 's|\.\./\.\./integration/components/|../../../../../.obi-src/internal/test/integration/components/|g' "$file"

        # Repo root context: ../../../.. (OBI root from oats subdir) → .obi-src
        # Anchored to end-of-line to avoid matching other patterns
        sed_i -e 's|context: \.\./\.\./\.\./\.\.$|context: ../../../../../.obi-src|' "$file"

        # OBI Dockerfile → Beyla Dockerfile
        sed_i -e "s|dockerfile: \./${OBI_DOCKERFILE}|dockerfile: ./${BEYLA_DOCKERFILE}|" "$file"
        sed_i -e "s|dockerfile: ${OBI_DOCKERFILE}|dockerfile: ${BEYLA_DOCKERFILE}|" "$file"

        # NOTE: testoutput volume paths (../../../../testoutput) are NOT adjusted here.
        # They are adjusted in a post-behavioral-transform fixup to avoid double-adjustment
        # by the BEHAVIORAL_TRANSFORMS testoutput depth entry.

        # When context points to .obi-src but dockerfile is Beyla (in beyla_extensions),
        # use repo root as context instead (Beyla Dockerfile lives in Beyla repo, not .obi-src).
        awk '{
            if (prev ~ /context:.*\.obi-src/ && $0 ~ /beyla_extensions\/components\/(beyla|beyla-k8s-cache)\/Dockerfile/) {
                sub(/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.obi-src/, "../../../../..", prev)
            }
            if (NR > 1) print prev
            prev = $0
        } END { print prev }' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
    done
}

rewrite_oats_go_mod() {
    echo "  Rewriting OATs go.mod files..."
    find "$OATS_DEST" -name "go.mod" -type f | while read -r modfile; do
        # Rewrite module path: OBI → Beyla convention (no /v3 for standalone test modules)
        sed_i -e "s|module ${OBI_MODULE}/internal/test/oats|module github.com/grafana/beyla/internal/obi/test/oats|g" "$modfile"
    done
}

transform_oats_go_files() {
    local jobs="$1"
    echo "  Transforming OATs Go files..."
    # Apply Go import transforms (safety net for future OATs that might import OBI packages)
    find "$OATS_DEST" -name "*.go" -type f 2>/dev/null | while read -r file; do
        sed_i -e "s|${OBI_MODULE}/internal/test|${BEYLA_MODULE}/internal/obi/test|g" "$file"
    done
    # Strip copyright headers
    find "$OATS_DEST" -name "*.go" -type f | run_parallel "$jobs" strip_headers
}

apply_oats_behavioral_transforms() {
    local jobs="$1"
    echo "  Applying OBI → Beyla behavioral transforms to OATs..."
    find "$OATS_DEST" -type f \( -name "*.go" -o -name "*.yml" -o -name "*.yaml" \) | run_parallel "$jobs" apply_transforms "${BEHAVIORAL_TRANSFORMS[@]}"
}

fixup_oats_testoutput_paths() {
    # OATs compose files at internal/obi/test/oats/SUBDIR/ need 5 levels of ../
    # to reach repo root. The OBI source has ../../../../testoutput (4 levels).
    # BEHAVIORAL_TRANSFORMS won't match (it looks for 5 levels), so the path is
    # still ../../../../testoutput after behavioral transforms. Fix it here.
    echo "  Fixing OATs testoutput volume paths..."
    find "$OATS_DEST" -name "docker-compose*.yml" | while read -r file; do
        sed_i -e 's|\.\./\.\./\.\./\.\./testoutput|../../../../../testoutput|g' "$file"
    done
}

# =============================================================================
# VM FUNCTIONS
# =============================================================================

copy_vm() {
    echo "  Copying VM test infrastructure..."
    if [[ -d "$VM_SRC" ]]; then
        rm -rf "$VM_DEST"
        mkdir -p "$VM_DEST"
        cp -r "$VM_SRC"/* "$VM_DEST/"

        # Adjust REPO_ROOT: generated vm is one level deeper than upstream
        # (internal/obi/test/vm/ = 4 levels vs internal/test/vm/ = 3 levels)
        if [[ -f "$VM_DEST/Makefile" ]]; then
            sed_i -e 's|REPO_ROOT ?= \.\./\.\./\.\.|REPO_ROOT ?= ../../../..|' \
                "$VM_DEST/Makefile"
        fi
    fi
}

generate() {
    echo "Generating OBI tests from $OBI_SRC..."
    local jobs
    jobs="$(determine_jobs)"
    echo "  Using $jobs parallel worker(s) for file transforms..."

    ensure_source_exists
    prepare_destination
    copy_upstream_files
    copy_beyla_manifests
    copy_discovered_go_subpackages
    copy_test_tools
    copy_beyla_extensions
    transform_go_imports_and_paths "$jobs"
    apply_component_consolidation
    adjust_docker_compose_paths
    ensure_multiexec_local_image_reuse
    split_docker_build_contexts
    apply_behavioral_transforms "$jobs"
    ensure_daemonset_process_metrics_enabled
    ensure_otherinstance_has_service_version
    cleanup_and_inject_build_tags "$jobs"

    # -----------------------------------------------------------------
    # OATs generation
    # -----------------------------------------------------------------
    copy_oats
    adjust_oats_compose_paths
    rewrite_oats_go_mod
    transform_oats_go_files "$jobs"
    apply_oats_behavioral_transforms "$jobs"
    fixup_oats_testoutput_paths

    # -----------------------------------------------------------------
    # VM test infrastructure
    # -----------------------------------------------------------------
    copy_vm

    echo "Done. Generated OBI tests at $OBI_DEST"
    echo "Done. Generated OATs at $OATS_DEST"
    echo ""
    echo "To run OBI tests: make test-integration-obi"
}

apply_component_path_transform() {
    local file="$1"
    sed_i -e 's|path\.Join(pathRoot, "internal", "test", "integration", "components",|path.Join(pathObiSrc, "internal", "test", "integration", "components",|g' \
        "$file"
}

strip_headers() {
    local file="$1"
    sed_i \
        -e '/^\/\/ Copyright The OpenTelemetry Authors/d' \
        -e '/^\/\/ SPDX-License-Identifier:/d' \
        "$file"
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
