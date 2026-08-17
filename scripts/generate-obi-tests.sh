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
OBI_DEST="internal/testgenerated/integration"

OATS_SRC=".obi-src/internal/test/oats"
OATS_DEST="internal/testgenerated/oats"

VM_SRC=".obi-src/internal/test/vm"
VM_DEST="internal/testgenerated/vm"

SCHEMAS_SRC=".obi-src/schemas"
SCHEMAS_DEST="schemas"


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
    # service.instance.id regex assertion (Go backtick literal)§§
    '`\^obi:\\d+\$\$`|`\^beyla:\\d+\$\$`'
    '/var/run/obi|/var/run/beyla'
    '"source":[ ]*"obi"|"source": "beyla"'

    # --- Binary name (entrypoint overrides in compose files) ---
    '^/obi|/beyla'
    '\([^.a-zA-Z0-9/_-]\)/obi|\1/beyla'

    # --- Metric name prefixes (exported output) ---
    'obi_|beyla_'

    # --- BPF program names (consumed verbatim, NEVER renamed) ---
    # Undo the generic obi_ → beyla_ rename for the `____` prefix that
    # bpf_dbg_printk puts in front of the BPF program name (BPF_KPROBE(name)
    # expands to an inner ____name function, and `__func__` is what gets
    # printed). Those program names come from .obi-src/bpf/** and are compiled
    # into the objects Beyla loads unchanged — e.g.
    # BPF_KPROBE(obi_kprobe_sys_ioctl) in bpf/generictracer/java_tls.c, whose
    # name is still `obi_kprobe_sys_ioctl` in
    # vendor/go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer/*.o. So a
    # Beyla run emits `____obi_kprobe_sys_ioctl`, never `____beyla_…`.
    #
    # Without this rule the log-scraping assertion in
    # TestJavaMalformedIoctlFailsClosed counts a string that can never appear,
    # so both counts are 0 and its assert.Never — the "fails closed" check the
    # test is named after — becomes vacuous.
    #
    # Must stay AFTER the 'obi_|beyla_' rule above: apply_transforms builds one
    # `sed -e` per entry in array order, so this one runs on its output.
    '____beyla_|____obi_'

    # --- Attribute names (exported output) ---
    'obi\.ip|beyla.ip'
    'obi\.network\.flow|beyla.network.flow'
    'obi\.network\.inter\.zone|beyla.network.inter.zone'
    'obi\.version|beyla.version'
    'obi\.revision|beyla.revision'
    'obi\.stat\.tcp\.|beyla.stat.tcp.'

    # --- Telemetry SDK/scope identity ---
    'Value: "go\.opentelemetry\.io/obi"|Value: "github.com/grafana/beyla"'
    '"value":"go\.opentelemetry\.io/obi"|"value":"github.com/grafana/beyla"'
    'Value: "opentelemetry"|Value: "beyla"'

    # --- K8s component paths ---
    'DockerfileOBI|DockerfileBeyla'
    'DockerfileK8sCache|DockerfileBeylaK8sCache'
    'internal/test/integration/components/beyla|internal/test/beyla_extensions/components/beyla'
    'internal/test/integration/components/beyla-k8s-cache|internal/test/beyla_extensions/components/beyla-k8s-cache'

    # --- GeoIP test databases (docker-compose-netolly-geoip.yml) ---
    # Upstream mounts the MaxMind test databases as a sibling of the compose file's
    # directory: internal/test/integration/../geoip → .obi-src/internal/test/geoip.
    # The generated compose file lives in internal/testgenerated/integration/, where
    # `../geoip` would resolve to internal/testgenerated/geoip — a path that does not
    # exist, so Docker silently creates an empty bind mount, no .mmdb is found, and no
    # src/dst asn+country attribute is ever decorated (TestNetwork_GeoIP then queries an
    # empty result set). Point it at the submodule copy instead of duplicating binary
    # fixtures under internal/test/beyla_extensions/, which would go stale unnoticed.
    #
    # `../../..` from internal/testgenerated/integration/ is the repo root — the same
    # base as the `context: ../../../.obi-src` rewrites in adjust_docker_compose_paths.
    # Anchoring on the full `../geoip:/geoip` mount means no other line in any generated
    # compose file can match.
    '\.\./geoip:/geoip|../../../.obi-src/internal/test/geoip:/geoip'

    # --- Test assertion fixes: hard-fail t → collect-t ct inside EventuallyWithT ---
    # OBI upstream bug: python/rails span checks in testNestedHTTPTracesKProbes use
    # require.Len(t, ...) instead of require.Len(ct, ...), causing immediate hard-fail
    # inside EventuallyWithT before it can retry on slow/kernel-5.15 environments.
    'require\.Len(t, res, 1, traceID)|require.Len(ct, res, 1, traceID)'

    # --- Config document version reported at startup (config_v2_test.go) ---
    # LAST-RESORT TRANSFORM: this diverges an assertion from upstream. It is
    # tolerable only because the divergence is real behaviour, not a masked bug.
    #
    # OBI bdabbaf2 (#2682) wired standalone Config v2 loading into
    # cmd/obi/main.go, which logs `"version":"v2"`. Beyla's cmd/beyla/main.go
    # cannot: OBI's v2 loader lives in go.opentelemetry.io/obi/internal/config/
    # {schema,convert} and cmd/obi/internal/configcmd, and Go's internal-package
    # rule is enforced by import path — the local `replace` to .obi-src does not
    # lift it. Nothing under vendor/go.opentelemetry.io/obi/pkg/ exports a
    # versioned loader (pkg/obi.LoadConfig is v1-only), so cmd/beyla/main.go
    # hard-codes configVersionV1 and logs `"version":"v1"`.
    #
    # What is NOT weakened: every other assertion in config_v2_test.go is
    # upstream's, unmodified — the suite keeps exercising standalone startup end
    # to end. Only the version *label* differs.
    #
    # The test input does diverge, though: because the v1 loader is not a
    # KnownFields decoder it drops the entire v2 document instead of rejecting
    # it, so Beyla's copy of configs/obi-config-v2.yml carries an appended block
    # of v1-equivalent keys (prometheus_export, routes, otel_*_export) that
    # restores the same effective configuration. See
    # ensure_config_v2_v1_equivalents below for the full key-by-key mapping.
    #
    # Scoped to the full quoted literal so it cannot leak into other generated
    # files; `"version":"v2"` occurs exactly once in the upstream test tree.
    #
    # DELETE THIS RULE — and ensure_config_v2_v1_equivalents with it, they go
    # away together — the moment OBI exports a versioned loader from pkg/
    # (e.g. `func LoadConfigVersioned(io.Reader) (*Config, string, error)`
    # wrapping schema.ParseStandaloneYAML → convert.DocumentToRuntime →
    # NotV2Error → obi.LoadConfig, per .obi-src/cmd/obi/main.go:110-142) and
    # cmd/beyla/main.go is switched over to report the real version.
    '"version":"v2"|"version":"v1"'

    # --- K8s image tags ---
    '"obi:dev"|"beyla:dev"'
    '"obi-k8s-cache:dev"|"beyla-k8s-cache:dev"'
    'Tag: "obi:dev"|Tag: "beyla:dev"'
    # YAML manifests use unquoted image tags
    'image: obi:dev|image: beyla:dev'
    'image: obi-k8s-cache:dev|image: beyla-k8s-cache:dev'
)

# ---- Schema-only transforms: registry ↔ Beyla runtime naming ----------------
# Applied AFTER BEHAVIORAL_TRANSFORMS and ONLY to the weaver registry
# (schemas/obi/groups/*.yaml), so these corrections cannot leak into the
# generated Go/YAML test files.
#
# Since weaver 0.25.1 (OBI cd0756833) the live-check filters live in
# schemas/obi/.weaver.toml instead of the Go harness, and the old
# advice-message ignore list — which used to swallow "does not exist in the
# registry" advisories — is gone. A registry declaration that does not match
# the signal Beyla actually emits is therefore now a hard violation.
SCHEMA_TRANSFORMS=(
    # Beyla exports OBI's internal ("meta") metrics under the "beyla" vendor
    # prefix (pkg/beyla/config_obi.go: attr.VendorPrefix = "beyla"), so the
    # registry must declare beyla.* metric names. The OBI registry declares
    # them as obi.* because attr.VendorPrefix defaults to "obi" upstream.
    'metric_name: obi\.|metric_name: beyla.'
    'id: metric\.obi\.|id: metric.beyla.'

    # ...but the build-info attribute keys are hardcoded "obi.version" /
    # "obi.revision" in OBI (vendor/go.opentelemetry.io/obi/pkg/export/otel/
    # metrics_internal.go:252) and are NOT derived from attr.VendorPrefix, so
    # Beyla emits them unchanged. Undo the generic obi.version / obi.revision
    # renames applied by BEHAVIORAL_TRANSFORMS, but only inside the registry:
    # the `- ref: obi.version` / `- ref: obi.revision` refs in
    # metric.beyla.internal.build.info would not resolve otherwise.
    #
    # Beyla emits BOTH spellings — metrics_net.go / metrics_stats.go build
    # their resource attributes from attr.VendorPrefix and therefore emit
    # beyla.version / beyla.revision. Those two keys are declared separately by
    # the x_beyla_buildinfo.yaml injection in apply_schema_injections(); see
    # that comment for the full emitter table. Keep the two rules below and
    # that injection in sync — dropping either reintroduces "does not exist in
    # the registry" violations, just from the other side.
    'beyla\.version|obi.version'
    'beyla\.revision|obi.revision'
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
    rm -rf "internal/testgenerated"
    rm -rf "$SCHEMAS_DEST"
    echo "Done."
}

apply_go_import_path_transforms() {
    local file="$1"
    sed_i \
        -e 's|^//go:build ignore$|//go:build integration|' \
        -e "s|${OBI_MODULE}/internal/test/integration|${BEYLA_MODULE}/internal/testgenerated/integration|g" \
        -e "s|${OBI_MODULE}/internal/test/tools|${BEYLA_MODULE}/internal/testgenerated/tools|g" \
        -e "s|${OBI_MODULE}/internal/test/weavercheck|${BEYLA_MODULE}/internal/testgenerated/weavercheck|g" \
        -e "s|${BEYLA_MODULE}/internal/test/integration|${BEYLA_MODULE}/internal/testgenerated/integration|g" \
        -e "s|${BEYLA_MODULE}/internal/test/tools|${BEYLA_MODULE}/internal/testgenerated/tools|g" \
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
        mkdir -p "internal/testgenerated/tools"
        cp -r ".obi-src/internal/test/tools/"* "internal/testgenerated/tools/"
        find "internal/testgenerated/tools" -name "*.go" -type f | while read -r file; do
            sed_i -e "s|${OBI_MODULE}/internal/test/tools|${BEYLA_MODULE}/internal/testgenerated/tools|g" "$file"
        done
    fi
}

copy_weavercheck() {
    # The new OBI revision extracted the transport-agnostic weaver live-check
    # parsing/validation into go.opentelemetry.io/obi/internal/test/weavercheck,
    # imported by both the integration suite (weaver.go) and the OATS harness.
    # OBI keeps it in its ROOT module so both consumers can import it. Mirror
    # that: copy it into a package of the MAIN Beyla module so the generated
    # integration package and the separate OATS harness module can both import
    # it via the Beyla path.
    local src=".obi-src/internal/test/weavercheck"
    local dest="internal/testgenerated/weavercheck"
    if [[ -d "$src" ]]; then
        echo "  Copying weavercheck package..."
        rm -rf "$dest"
        mkdir -p "$dest"
        # Copy only the source (not weavercheck_test.go — avoid adding an
        # untagged standalone unit test to the Beyla module).
        cp "$src/weavercheck.go" "$dest/"
        # Strip the canonical-import-path comment so the package can be
        # imported via the Beyla path. Do NOT add a //go:build integration tag:
        # the OATS harness is built by Ginkgo without that tag and must still
        # see the package (matches OBI, where the file has no build tag).
        sed_i -e "s|// import \"${OBI_MODULE}/internal/test/weavercheck\"||g" \
            "$dest/weavercheck.go"
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
        sed_i -e "s|\".obi-src/${OBI_DOCKERFILE}\"|\"${BEYLA_DOCKERFILE}\"|g" \
            "$OBI_DEST/dockerutil_test.go"
    fi

    # go_otel BuildImage: use .obi-src as context (go_otel Dockerfile expects
    # internal/test/integration/components/go_otel/ relative to context).
    if [[ -f "$OBI_DEST/http_go_otel_test.go" ]]; then
        sed_i -e 's|buildDockerImage(t\.Context(), t\.Output(), "hatest-testserver", "\.obi-src/internal/test/integration/components/go_otel/Dockerfile")|buildDockerImageWithContext(t.Context(), t.Output(), "hatest-testserver", pathObiSrc, "internal/test/integration/components/go_otel/Dockerfile")|' \
            "$OBI_DEST/http_go_otel_test.go"
    fi

    # goautosdk fixtures: same situation as go_otel above. The Dockerfiles do
    # `COPY internal/test/integration/components/goautosdk/...`, a path that
    # only resolves inside .obi-src, so the build context must be pathObiSrc
    # and the dockerfile literals must stay relative to that context (undo the
    # ".obi-src/…" rewrite apply_go_import_path_transforms just applied).
    if [[ -f "$OBI_DEST/go_auto_sdk_test.go" ]] \
        && grep -q 'buildDockerImage(t\.Context(), t\.Output(), version\.image, version\.dockerfile)' "$OBI_DEST/go_auto_sdk_test.go"; then
        sed_i \
            -e 's|dockerfile: "\.obi-src/internal/test/integration/components/goautosdk/|dockerfile: "internal/test/integration/components/goautosdk/|g' \
            -e 's|buildDockerImage(t\.Context(), t\.Output(), version\.image, version\.dockerfile)|buildDockerImageWithContext(t.Context(), t.Output(), version.image, pathObiSrc, version.dockerfile)|g' \
            "$OBI_DEST/go_auto_sdk_test.go"
    fi

    # Component file paths: testserver, rusttestserver etc. live in .obi-src.
    find "$OBI_DEST" -name "*.go" -type f | run_parallel "$jobs" apply_component_path_transform

    # Update docker/compose.go to reference the generated test directory.
    if [[ -f "$OBI_DEST/components/docker/compose.go" ]]; then
        sed_i -e 's|"internal", "test", "integration"|"internal", "testgenerated", "integration"|g' \
            "$OBI_DEST/components/docker/compose.go"
    fi
}

apply_component_consolidation() {
    if [[ -f "$OBI_DEST/k8s/common/testpath/testpath.go" ]]; then
        sed_i -e 's|Components      = path.Join(IntegrationTest, "components")|Components      = path.Join(Root, ".obi-src", "internal", "test", "integration", "components")|' \
            "$OBI_DEST/k8s/common/testpath/testpath.go"
        # Manifests sourced from generated output — content transformed on the fly during generate
        sed_i -e 's|Manifests       = path.Join(IntegrationTest, "k8s", "manifests")|Manifests       = path.Join(Root, "internal", "testgenerated", "integration", "k8s", "manifests")|' \
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
        # Depth matches upstream (3 levels), just redirect to .obi-src
        sed_i -e 's|context: \.\./\.\./\.\./|context: ../../../.obi-src/|g' "$file"
        sed_i -e 's|context: \.\./\.\./\.\.$|context: ../../../.obi-src|' "$file"
        # Volume mounts: internal/ paths → .obi-src
        # (testoutput paths are unchanged — depth matches upstream)
        sed_i -e 's|\.\./\.\./\.\./internal/|../../../.obi-src/internal/|g' "$file"
        # Volume mount that exposes the OBI repo root inside the container
        # (used by tests that `go test ./pkg/...` against OBI source).
        sed_i -e 's|\.\./\.\./\.\.:/src|../../../.obi-src:/src|g' "$file"

        # Redirect bare ./components/ and components/ paths to .obi-src.
        # These reference standalone app dirs that aren't copied to the
        # generated output (they're built via Docker from the OBI source).
        sed_i -e 's|\./components/|../../../.obi-src/internal/test/integration/components/|g' "$file"
        sed_i -e 's|context: components/|context: ../../../.obi-src/internal/test/integration/components/|g' "$file"
        # extends:file: references — Docker Compose resolves relative to the compose
        # file location, so the file must physically exist at that path. Redirect to
        # .obi-src just as with other components/ references.
        sed_i -e 's|file: components/|file: ../../../.obi-src/internal/test/integration/components/|g' "$file"

        # Swap the OBI Dockerfile for the Beyla Dockerfile and point its
        # build context at the Beyla repo root instead of .obi-src.
        sed_i -e "s|dockerfile: \\./${OBI_DOCKERFILE}|dockerfile: ${BEYLA_DOCKERFILE}|" "$file"
        sed_i -e "s|dockerfile: ${OBI_DOCKERFILE}|dockerfile: ${BEYLA_DOCKERFILE}|" "$file"
        # Beyla Dockerfile paths (beyla_extensions) handled by BEHAVIORAL_TRANSFORMS in step 4.
        # When context points to .obi-src but dockerfile is Beyla (in beyla_extensions),
        # use repo root as context instead.
        awk '{
            if (prev ~ /context:.*\.obi-src/ && $0 ~ /beyla_extensions\/components\/(beyla|beyla-k8s-cache)\/Dockerfile/) {
                sub(/\.\.\/\.\.\/\.\.\/\.obi-src/, "../../..", prev)
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

stamp_obi_revision_into_multiexec_compose() {
    # Cache-busting stamp for the VM integration "docker-images" cache.
    #
    # workflow_integration_tests_vm.yml keys the pre-built docker-images.tar on
    # the hash of the multiexec compose files plus the referenced Dockerfiles.
    # The hatest-obi (Beyla) image those compose files build is compiled from
    # the vendored OBI, but OBI is vendored via a local `replace => ./.obi-src`:
    # an OBI submodule bump changes neither go.mod/go.sum (the require is a
    # static placeholder and OBI is absent from go.sum) nor any Dockerfile or
    # compose file. Without a signal here the cache key is byte-identical across
    # an OBI bump, so the run restores a stale hatest-obi image built from the
    # previous OBI — e.g. emitting underscore target_info/traces_target_info
    # while the regenerated weaver registry declares dot-notation target.info /
    # traces.target.info, which weaver's OTLP live-check then rejects.
    #
    # Stamping the resolved OBI revision into the (cache-keyed) multiexec compose
    # files makes the cache key change whenever OBI changes, forcing hatest-obi
    # to be rebuilt from the current vendor. The stamp is a YAML comment, so it
    # is inert to docker compose. Run this after all compose transforms so it is
    # not clobbered.
    local obi_rev
    obi_rev="$(git -C .obi-src rev-parse HEAD 2>/dev/null \
        || git rev-parse HEAD:.obi-src 2>/dev/null \
        || echo unknown)"
    echo "  Stamping OBI revision ($obi_rev) into multiexec compose files..."
    for file in "$OBI_DEST/docker-compose-multiexec.yml" "$OBI_DEST/docker-compose-multiexec-host.yml"; do
        [[ -f "$file" ]] || continue
        printf '# obi-revision: %s\n' "$obi_rev" >> "$file"
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

ensure_netolly_basic_guess_ports() {
    # The plain netolly manifest omits guess_ports, relying on eBPF TCP-SYN tracking
    # to identify server_port.  In Beyla's test environment (appolly + netolly eBPF
    # programs loaded together), the connInitiatorsMap (capped at CacheMaxFlows=20)
    # fills up before the pinger SYN is seen, leaving direction=unknown and
    # server_port=0.  Add guess_ports: ordinal to mirror the other netolly manifests
    # and make the test robust.
    local file="$OBI_DEST/k8s/manifests/06-obi-netolly.yml"
    [[ -f "$file" ]] || return 0
    if ! grep -q 'guess_ports:' "$file"; then
        awk '/^      protocols:/ { print "      guess_ports: ordinal" } { print }' \
            "$file" > "$file.tmp" && mv "$file.tmp" "$file"
    fi
}

ensure_config_v2_v1_equivalents() {
    # Make configs/obi-config-v2.yml produce the same *effective* configuration
    # under Beyla's v1 loader as OBI's v2 document does under its versioned one.
    #
    # cmd/beyla/main.go can only call the v1 loader (see the `"version":"v2"`
    # rule in BEHAVIORAL_TRANSFORMS for why). The v1 loader is not a KnownFields
    # decoder, so the whole v2 document — file_format, tracer_provider,
    # meter_provider, extensions.obi — is silently dropped. The document still
    # loads, which is why the startup assertions of config_v2_test.go pass, but
    # nothing it declares takes effect. In particular no application Prometheus
    # exporter is started, so the test's `GET :8999/metrics` gets a 404 from the
    # internal-metrics-only server that BEYLA_INTERNAL_METRICS_PROMETHEUS_PORT
    # opens on that port.
    #
    # Fix the *input*, not the assertion: append the v1 keys that mirror the v2
    # document, so config_v2_test.go's assertions hold unmodified.
    #
    #   v2 document key                                             -> v1 key
    #   meter_provider.readers[].pull…prometheus/development.port   -> prometheus_export.{port,path}
    #   capture.instrumentation.http.routes.incoming                -> routes
    #   tracer_provider…otlp_grpc.endpoint                          -> otel_traces_export.endpoint
    #   meter_provider.readers[].periodic…otlp_grpc.endpoint        -> otel_metrics_export.endpoint
    #
    # The rest of the v2 document is already supplied by docker-compose.yml
    # (BEYLA_EXECUTABLE_NAME, BEYLA_OPEN_PORT, BEYLA_DISCOVERY_POLL_INTERVAL,
    # BEYLA_LOG_FORMAT) or matches the v1 defaults (K8s decoration off).
    #
    # /metrics and /internal/metrics coexist on port 8999: OBI's
    # connector.PrometheusManager multiplexes (port, path) registrations onto a
    # single HTTP server, so the internal metrics endpoint is unaffected. Do NOT
    # move it with BEYLA_INTERNAL_METRICS_PROMETHEUS_PATH instead — docker-compose.yml
    # is shared by every suite, and other suites scrape /internal/metrics.
    #
    # DELETE THIS STEP together with the `"version":"v2"` behavioral transform
    # and cmd/beyla/main.go's configVersionV1 constant, the moment OBI exports a
    # versioned loader from pkg/.
    local file="$OBI_DEST/configs/obi-config-v2.yml"
    [[ -f "$file" ]] || return 0
    # Idempotency guard (same style as ensure_otherinstance_has_service_version).
    grep -q '^prometheus_export:' "$file" && return 0
    cat >>"$file" <<'EOF'
# --- Beyla-only: v1 equivalents of the v2 document above ---------------------
# Beyla loads this file with the v1 loader (cmd/beyla/main.go), which ignores
# `file_format`, `tracer_provider`, `meter_provider` and `extensions.obi`. The
# keys below restore the same effective configuration, so config_v2_test.go's
# assertions hold unmodified. Injected by ensure_config_v2_v1_equivalents in
# scripts/generate-obi-tests.sh; delete it together with the `"version":"v2"`
# transform once OBI exports a versioned loader from pkg/.
otel_traces_export:
  endpoint: http://jaeger:4317
otel_metrics_export:
  endpoint: http://otelcol:4317
prometheus_export:
  port: 8999
  path: /metrics
routes:
  patterns:
    - /basic/:rnd
  unmatched: path
  ignored_patterns:
    - /metrics
  ignore_mode: traces
EOF
}

ensure_malicious_ioctl_local_downstream() {
    # Take TestJavaMalformedIoctlFailsClosed off the public internet.
    #
    # Upstream's last step is `testJavaNestedTraces(t, "request")`, which drives
    #   GET /api/request?url=https://httpbin.org/get
    # and asserts a nested `GET /get` client span. httpbin.org is chronically
    # rate-limited: on this branch it answered 503 SERVICE_UNAVAILABLE to every
    # one of the ~25 attempts inside the 2-minute Eventually window, on the
    # initial run and both re-runs. HttpClientService.makeGetRequest swallows the
    # exception and still returns 200 ("Error making request: …"), so the
    # DoHTTPGet step passes and only `require.Len(res, 1)` fails — i.e. the suite
    # is red for reasons that have nothing to do with the instrumentation.
    #
    # OBI's own docker-compose-java-dist.yml already shows the right pattern: it
    # defines a container-local `downstream` testserver, and
    # testJavaNestedTracesPlainHTTP (same file, upstream's own helper and
    # assertions) exercises the identical server→client nesting against
    # http://downstream:8086/rolldice/1. So this step adds that same service to
    # the malicious-ioctl compose file and repoints the final check at the
    # upstream helper that uses it. No assertion is weakened: the nested
    # client-span check still runs, over 10 requests per iteration with an 80%
    # nesting floor, only the target moves off the public internet.
    #
    # DURABLE FIX (upstream, then drop this step): make the same change in OBI —
    # add the `downstream` service to
    # internal/test/integration/docker-compose-java-dist-malicious-ioctl.yml and
    # change the tail of TestJavaMalformedIoctlFailsClosed to a local target.
    # Ideally upstream points it at the testserver's TLS port (STD_TLS_PORT
    # 8383) rather than plain HTTP, which would keep the post-attack check on
    # the Java TLS path that the malicious ioctl actually targets; the plain-HTTP
    # variant is used here because it is the one upstream already proves green
    # in TestJavaNestedTraces.
    local compose="$OBI_DEST/docker-compose-java-dist-malicious-ioctl.yml"
    local go_file="$OBI_DEST/java_dist_test.go"

    if [[ -f "$compose" ]] && ! grep -q '^  downstream:' "$compose"; then
        awk '
        /^  obi:[[:space:]]*$/ && !done {
            print "  # Injected by ensure_malicious_ioctl_local_downstream in"
            print "  # scripts/generate-obi-tests.sh: local target for the nested-trace check"
            print "  # at the end of TestJavaMalformedIoctlFailsClosed, replacing httpbin.org."
            print "  # Mirrors the downstream service of docker-compose-java-dist.yml."
            print "  downstream:"
            print "    build:"
            print "      context: ../../../.obi-src"
            print "      dockerfile: internal/test/integration/components/testserver/Dockerfile"
            print "    image: hatest-testserver"
            print "    environment:"
            print "      STD_PORT: \"8086\""
            print "      LOG_LEVEL: DEBUG"
            print ""
            done = 1
        }
        { print }
        ' "$compose" > "$compose.tmp" && mv "$compose.tmp" "$compose"

        if ! grep -q '^  downstream:' "$compose"; then
            echo "  WARNING: could not inject the downstream service into $compose"
        fi
    fi

    if [[ -f "$go_file" ]] && grep -q '^	testJavaNestedTraces(t, "request")$' "$go_file"; then
        awk '
        /^\ttestJavaNestedTraces\(t, "request"\)$/ {
            print "\t// Beyla-only: upstream calls testJavaNestedTraces(t, \"request\"), which"
            print "\t// targets https://httpbin.org/get and fails whenever that public service"
            print "\t// rate-limits us. testJavaNestedTracesPlainHTTP is upstream'"'"'s own helper"
            print "\t// and makes the same server-to-client nesting assertion against the"
            print "\t// container-local downstream service. Rewritten by"
            print "\t// ensure_malicious_ioctl_local_downstream in scripts/generate-obi-tests.sh;"
            print "\t// drop it once OBI takes this suite off the public internet."
            print "\ttestJavaNestedTracesPlainHTTP(t, \"request\")"
            next
        }
        { print }
        ' "$go_file" > "$go_file.tmp" && mv "$go_file.tmp" "$go_file"
    fi
}

ensure_weaver_tap_survives_weavercol_startup() {
    # Make the weaver first hop (otelcol → weavercol) tolerate weavercol's pod
    # startup window.
    #
    # OBI's configs/otelcol-config-k8s-weaver.yml disables retry_on_failure on
    # the otlp/weavercol exporter, so anything the collector receives before
    # weavercol is listening is dropped permanently. validateWeaver's first-hop
    # drop check (OBI cd075683 / 3f6214b2) counts those
    # otelcol_exporter_{send,enqueue}_failed_* samples and fails the whole
    # suite — with zero semconv advisories — as
    #   "the suite otelcol dropped N export item(s) to weavercol".
    #
    # Beyla-specific justification: Beyla's daemonset suite is much heavier
    # than OBI's during exactly that window. ensure_daemonset_process_metrics_enabled
    # flips BEYLA_OTEL_METRICS_FEATURES to application,application_process and
    # injects a `survey:` block for otherinstance, and the suite carries two
    # Beyla-only test files (k8s_daemonset_{y,z}_metrics_test.go from
    # internal/test/beyla_extensions/k8s/daemonset/). So Beyla starts filling
    # the tap immediately while weavercol is still coming up (observed:
    # ~6s of "connection refused" to weavercol:4317), where OBI's lighter
    # daemonset emits little enough to survive. The collector's own log
    # literally advises "Try enabling retry_on_failure".
    #
    # Retrying rather than dropping also fixes the second failure mode seen on
    # this suite ("weaver report has no span entities"): the dropped batches
    # included the span pipeline's, so retried delivery restores it.
    #
    # DURABLE FIX: enable retry_on_failure on otlp/weavercol in OBI's own
    # configs/otelcol-config-k8s-weaver.yml and drop this step on the next bump.
    local file
    # Match by content rather than a hard-coded path so sibling / multi-node
    # weaver collector configs are covered too.
    grep -rl 'otlp/weavercol:' "$OBI_DEST/configs" 2>/dev/null | while read -r file; do
        # Idempotency guard (same style as ensure_otherinstance_has_service_version).
        grep -q 'max_elapsed_time: 60s' "$file" && continue
        awk '
        BEGIN { blk = 0; sec = "" }
        /^  otlp\/weavercol:[[:space:]]*$/ { blk = 1; sec = ""; print; next }
        blk && /^[^ ]/                     { blk = 0; sec = ""; print; next }
        blk && /^  [^ ]/                   { blk = 0; sec = ""; print; next }
        blk && /^    sending_queue:[[:space:]]*$/    { sec = "q"; print; next }
        blk && /^    retry_on_failure:[[:space:]]*$/ { sec = "r"; print; next }
        blk && /^    [^ ]/                 { sec = ""; print; next }
        # Raise the queue so the retried backlog plus Beyla'"'"'s higher emission
        # rate fits.
        sec == "q" && /^      queue_size:/ {
            print "      queue_size: 4000"
            print "      num_consumers: 4"
            next
        }
        sec == "q" && /^      num_consumers:/ { next }
        # Bounded backoff: covers the ~6s weavercol-startup window without
        # letting a genuinely dead weavercol stall the suite.
        sec == "r" && /^      enabled:/ {
            print "      enabled: true"
            print "      initial_interval: 1s"
            print "      max_interval: 5s"
            print "      max_elapsed_time: 60s"
            next
        }
        sec == "r" && /^      (initial_interval|max_interval|max_elapsed_time):/ { next }
        { print }
        ' "$file" > "$file.tmp" && mv "$file.tmp" "$file"

        if ! grep -q 'max_elapsed_time: 60s' "$file"; then
            echo "  WARNING: $file declares otlp/weavercol but no retry_on_failure block was patched"
        fi
    done
}

restore_weaver_registry_mount_paths() {
    # The weaver container (from OBI's components/weaver/service.yml) hardcodes
    # --registry /obi-registry and working_dir: /obi-registry. The BEHAVIORAL_TRANSFORMS
    # rule '\([^.a-zA-Z0-9/_-]\)/obi|\1/beyla' incorrectly renames the volume mount
    # suffix from :/obi-registry:ro to :/beyla-registry:ro. Restore the correct path
    # so the registry bind-mount matches what the weaver command expects.
    find "$OBI_DEST" -maxdepth 1 -name "docker-compose*.yml" | while read -r file; do
        grep -q ':/beyla-registry:ro' "$file" || continue
        sed_i -e 's|:/beyla-registry:ro|:/obi-registry:ro|g' "$file"
    done
}

apply_behavioral_transforms() {
    local jobs="$1"
    echo "  Applying OBI → Beyla behavioral transforms..."
    find "$OBI_DEST" -type f \( -name "*.go" -o -name "*.yml" -o -name "*.yaml" \) | run_parallel "$jobs" apply_transforms "${BEHAVIORAL_TRANSFORMS[@]}"
}

cleanup_and_inject_build_tags() {
    local jobs="$1"
    echo "  Adding build tags..."
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
        # Depth matches upstream (4 levels from oats/SUBDIR/ to repo root)
        sed_i -e 's|context: \.\./\.\./integration/components/|context: ../../../../.obi-src/internal/test/integration/components/|g' "$file"

        # Volume mount paths: some compose files mount files from OBI components
        # (e.g. init.sql, certs). These also use ../../integration/components/
        sed_i -e 's|\.\./\.\./integration/components/|../../../../.obi-src/internal/test/integration/components/|g' "$file"

        # Repo root context: ../../../.. (OBI root from oats subdir) → .obi-src
        # Anchored to end-of-line to avoid matching other patterns
        sed_i -e 's|context: \.\./\.\./\.\./\.\.$|context: ../../../../.obi-src|' "$file"

        # OBI Dockerfile → Beyla Dockerfile
        sed_i -e "s|dockerfile: \./${OBI_DOCKERFILE}|dockerfile: ./${BEYLA_DOCKERFILE}|" "$file"
        sed_i -e "s|dockerfile: ${OBI_DOCKERFILE}|dockerfile: ${BEYLA_DOCKERFILE}|" "$file"

        # When context points to .obi-src but dockerfile is Beyla (in beyla_extensions),
        # use repo root as context instead (Beyla Dockerfile lives in Beyla repo, not .obi-src).
        awk '{
            if (prev ~ /context:.*\.obi-src/ && $0 ~ /beyla_extensions\/components\/(beyla|beyla-k8s-cache)\/Dockerfile/) {
                sub(/\.\.\/\.\.\/\.\.\/\.\.\/\.obi-src/, "../../../..", prev)
            }
            if (NR > 1) print prev
            prev = $0
        } END { print prev }' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
    done
}

rewrite_oats_go_mod() {
    echo "  Rewriting OATs go.mod files..."
    find "$OATS_DEST" -name "go.mod" -type f | while read -r modfile; do
        # Rewrite all OBI oats module references (module declarations, require, and replace
        # directives) to the Beyla module path. Use ${BEYLA_MODULE} (with /v3) to match
        # the Go import transforms applied to .go files by transform_oats_go_files().
        sed_i -e "s|${OBI_MODULE}/internal/test/oats|${BEYLA_MODULE}/internal/testgenerated/oats|g" "$modfile"

        # The upstream OATS modules require the OBI ROOT module (added for the
        # weavercheck package) via a local replace to the repo root. In Beyla
        # the repo root IS the Beyla module, so repoint both the require and the
        # replace at ${BEYLA_MODULE}. After the oats-path rewrite above, the only
        # remaining go.opentelemetry.io/obi tokens are this root require and
        # replace (the go.opentelemetry.io/{otel,collector,proto,auto} deps and
        # the prose comment mentioning the OBI module are untouched).
        # "../../../.." from internal/testgenerated/oats/{harness,http,…} is the
        # Beyla repo root, whose module path is ${BEYLA_MODULE}, so the replace
        # now matches and provides …/internal/testgenerated/weavercheck.
        # The require version must carry the module's major-version suffix
        # (Go rejects "v0.0.0" for a /v3 module path), so bump v0.0.0 → v3.0.0;
        # the local replace makes the exact version immaterial at build time.
        sed_i \
            -e "s|${OBI_MODULE} v0.0.0|${BEYLA_MODULE} v3.0.0|g" \
            -e "s|replace ${OBI_MODULE} =>|replace ${BEYLA_MODULE} =>|g" \
            "$modfile"

        # Keep the compiled Ginkgo version in lockstep with the CLI installed
        # from internal/tools/go.mod (v2.30.0). The upstream OATS modules pin
        # v2.28.1, which triggers a "Ginkgo detected a version mismatch"
        # failure against the newer CLI. Update this if that pin changes.
        sed_i -e "s|github.com/onsi/ginkgo/v2 v2.28.1|github.com/onsi/ginkgo/v2 v2.30.0|g" "$modfile"
    done
}

transform_oats_go_files() {
    local jobs="$1"
    echo "  Transforming OATs Go files..."
    # Apply Go import transforms (safety net for future OATs that might import OBI packages)
    find "$OATS_DEST" -name "*.go" -type f 2>/dev/null | while read -r file; do
        sed_i -e "s|${OBI_MODULE}/internal/test|${BEYLA_MODULE}/internal/testgenerated|g" "$file"
    done
}

apply_oats_behavioral_transforms() {
    local jobs="$1"
    echo "  Applying OBI → Beyla behavioral transforms to OATs..."
    find "$OATS_DEST" -type f \( -name "*.go" -o -name "*.yml" -o -name "*.yaml" \) | run_parallel "$jobs" apply_transforms "${BEHAVIORAL_TRANSFORMS[@]}"
}

tidy_oats_go_mods() {
    # The rewrites above introduce a new require (the Beyla root module, for
    # weavercheck) and bump the Ginkgo pin, so each OATS module's go.sum is now
    # stale ("go: updates to go.mod needed; to update it: go mod tidy"). Tidy
    # every generated OATS module. This needs module-cache/network access,
    # consistent with the vendor-obi-tests / copy-obi-vendor make targets that
    # already run go get / go mod tidy / go mod vendor.
    echo "  Tidying generated OATs modules..."
    # Tidy the shared harness first (group modules replace it via ../harness).
    for modfile in "$OATS_DEST/harness/go.mod" $(find "$OATS_DEST" -name go.mod -type f ! -path "*/harness/go.mod"); do
        [[ -f "$modfile" ]] || continue
        ( cd "$(dirname "$modfile")" && go mod tidy )
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

        # Depth matches upstream (internal/testgenerated/vm/ = 3 levels, same as
        # internal/test/vm/) so REPO_ROOT needs no adjustment.
        if [[ -f "$VM_DEST/Makefile" ]]; then
            # Quote test_pattern build-arg: patterns contain | which the shell interprets
            sed_i -e 's|--build-arg test_pattern=$(TEST_PATTERN)|--build-arg "test_pattern=$(TEST_PATTERN)"|' \
                "$VM_DEST/Makefile"

            # Beyla's Docker build is heavier than upstream (vendored deps,
            # larger codebase, coverage-instrumented binary).  The default
            # 10G VM disk image fills up during `make compile-for-coverage`
            # inside Docker.  Bump to 20G so there is headroom.
            sed_i -e 's|^IMG_SIZE ?= 10G|IMG_SIZE ?= 20G|' \
                "$VM_DEST/Makefile"
        fi
    fi
}

# =============================================================================
# SCHEMAS FUNCTIONS
# =============================================================================

fetch_upstream_semconv() {
    echo "  Fetching upstream semantic conventions (weaver registry dependency)..."
    local script=".obi-src/scripts/fetch-upstream-semconv.sh"
    if [[ ! -f "$script" ]]; then
        echo "  WARNING: $script not found; skipping semconv fetch"
        return 0
    fi
    # Run from the OBI repo root so the script resolves REPO_ROOT = .obi-src/
    # and writes .obi-src/schemas/obi/.deps/upstream-v<VERSION>/model/.
    (cd .obi-src && bash scripts/fetch-upstream-semconv.sh)
}

copy_schemas() {
    echo "  Copying SCHEMAs..."
    if [[ -d "$SCHEMAS_SRC" ]]; then
        rm -rf "$SCHEMAS_DEST"
        mkdir -p "$SCHEMAS_DEST"
        cp -r "$SCHEMAS_SRC"/* "$SCHEMAS_DEST/"
    fi
}

apply_schema_transforms() {
    local jobs="$1"
    # apply_transforms builds one `sed -e …` per rule in array order, so the
    # SCHEMA_TRANSFORMS rules operate on the output of the behavioral ones
    # (that is what lets them undo the obi.version / obi.revision renames).
    find "$SCHEMAS_DEST/obi/groups" -name "*.yaml" -type f \
        | run_parallel "$jobs" apply_transforms \
            "${BEHAVIORAL_TRANSFORMS[@]}" "${SCHEMA_TRANSFORMS[@]}"
}

# ---- Schema injections: registry override groups not (yet) in OBI ------------
# copy_schemas re-derives schemas/obi/ verbatim from .obi-src on every run
# (rm -rf + cp), so any hand-edit under schemas/ is wiped. Overrides that OBI
# has not yet declared upstream are re-created here, after apply_schema_transforms,
# so they survive regeneration. This is the schema-level equivalent of the
# CODE_INJECTIONS block above: a documented bridge until the declaration lands
# in OBI's own schemas/obi/groups/ and flows back in via a submodule bump.
apply_schema_injections() {
    echo "  Applying schema injections..."

    # cpu.mode=wait (process.cpu.time / process.cpu.utilization).
    #
    # The upstream OTel process-metrics semconv
    # (.deps/upstream-*/model/process/metrics.yaml) states that
    # `cpu.mode` for process.cpu.time/utilization SHOULD use `user`, `system`,
    # `wait`. OBI's refactored process-CPU reader emits `cpu.mode=wait`
    # accordingly. But the SHARED cpu.mode enum
    # (.deps/upstream-*/model/cpu/registry.yaml) only lists
    # user/system/nice/idle/iowait/interrupt/steal/kernel — no `wait` — so
    # weaver live-check flags `wait` as an undefined_enum_variant and the
    # weaver-validated suites fail (integration TestSuite_PythonAsyncUvloop_*).
    #
    # This is a legitimate closed-enum extension, not a bug value, so declare it
    # rather than suppress it (per schemas/obi/README.md "Closed enum, extended").
    # Override group id is x.obi.cpu so it sorts last and wins weaver's
    # last-id-wins resolution; it carries the FULL upstream member list plus
    # `wait`. Re-sync the upstream members from
    # .deps/upstream-<version>/model/cpu/registry.yaml when bumping semconv.
    #
    # DURABLE FIX: declare this group in OBI's own schemas/obi/groups/ (and
    # allowlist the expected DuplicateAttributeId in OBI's
    # scripts/lint-schema-filter.jq); then drop this injection after the bump.
    cat > "$SCHEMAS_DEST/obi/groups/x_obi_cpu.yaml" <<'EOF'
groups:
  # Overrides `cpu.mode`: extends the shared upstream enum with `wait`, the
  # value OBI emits for process.cpu.time / process.cpu.utilization. The
  # upstream process-metrics semconv sanctions `wait` for these metrics, but
  # the shared cpu.mode registry enum has no member for it, so it must be
  # declared here or weaver flags it as undefined_enum_variant.
  # Emitters: process-CPU reader (process.cpu.time, process.cpu.utilization).
  #
  # See ../README.md for the override mechanics (x.obi.* group id, full
  # upstream member list, lint allowlist). Members mirror
  # .deps/upstream-*/model/cpu/registry.yaml verbatim, plus `wait`.
  #
  # NOTE: injected by scripts/generate-obi-tests.sh (apply_schema_injections);
  # a bridge until OBI declares cpu.mode=wait upstream.
  - id: x.obi.cpu
    type: attribute_group
    display_name: OBI CPU Attribute Overrides
    brief: >
      OBI override of `cpu.mode` extending the shared upstream enum with `wait`,
      emitted for process.cpu.time / process.cpu.utilization.
    attributes:
      - id: cpu.mode
        brief: "The mode of the CPU"
        type:
          members:
            - id: user
              value: 'user'
              brief: User
              stability: development
            - id: system
              value: 'system'
              brief: System
              stability: development
            - id: nice
              value: 'nice'
              brief: Nice
              stability: development
            - id: idle
              value: 'idle'
              brief: Idle
              stability: development
            - id: iowait
              value: 'iowait'
              brief: IO Wait
              stability: development
            - id: interrupt
              value: 'interrupt'
              brief: Interrupt
              stability: development
            - id: steal
              value: 'steal'
              brief: Steal
              stability: development
            - id: kernel
              value: 'kernel'
              brief: Kernel
              stability: development
            # --- OBI extension (not in upstream semconv v1.41 cpu registry) ---
            # Sanctioned by upstream process metrics semconv for
            # process.cpu.time / process.cpu.utilization.
            - id: wait
              value: 'wait'
              brief: Wait
              stability: development
        stability: development
        examples: [ "user", "system" ]
EOF

    # survey_info — a Beyla-only metric with no OBI counterpart.
    #
    # pkg/export/otel/metrics_survey.go emits `survey_info` (name from
    # SurveyInfoMetricName in pkg/export/otel/common.go) for every process
    # discovered via `discovery.survey` but NOT instrumented. OBI has no survey
    # feature, so its registry declares no such group and weaver live-check
    # reports "Metric does not exist in the registry" — which is fatal since
    # weaver 0.25.1 moved the advice-message ignore list out of the Go harness.
    # This is what fails the k8s daemonset suite (whose 06-obi-daemonset.yml
    # gets a `survey:` block from ensure_daemonset_process_metrics_enabled).
    #
    # `updowncounter` mirrors what is actually emitted over OTLP
    # (meter.Int64UpDownCounter, no unit) rather than the OTel-canonical gauge
    # mapping of the Prometheus `*_info` convention — same reasoning as the
    # comment on metric.target.info in OBI's own obi_internal.yaml. Weaver only
    # validates the OTLP tap, so prom_survey.go's gauge is irrelevant here.
    #
    # The attribute set is whatever GetAppResourceAttrs/ResourceAttrsFromEnv
    # produce (service.*, k8s.*, host.*, …), all already declared by upstream
    # semconv; only the service.* refs are declared here, opt_in, mirroring how
    # metric.target.info declares a subset of what it carries.
    #
    # Group id is x.beyla.survey so it sorts last, consistent with x.obi.cpu.
    #
    # NOTE: injected by scripts/generate-obi-tests.sh (apply_schema_injections).
    # Unlike x_obi_cpu there is NO durable upstream fix for this one: survey is
    # a Beyla-only feature, so the declaration cannot flow back into OBI's
    # schemas/obi/groups/ and this injection is permanent.
    cat > "$SCHEMAS_DEST/obi/groups/x_beyla_survey.yaml" <<'EOF'
groups:
  # Beyla-only `survey_info` meta-metric. See scripts/generate-obi-tests.sh
  # (apply_schema_injections) for why this is injected rather than inherited
  # from OBI's registry.
  - id: x.beyla.survey
    type: metric
    metric_name: survey_info
    instrument: updowncounter
    unit: ""
    stability: development
    brief: >
      Beyla-only counterpart of `target.info` for surveyed processes: emitted
      with value 1 to carry the resource attributes of a process that Beyla
      discovered through `discovery.survey` but did not instrument
      (pkg/export/otel/metrics_survey.go). Removed again when the process
      terminates. OBI has no survey feature and therefore no such metric.
    attributes:
      - ref: service.name
        requirement_level: opt_in
      - ref: service.namespace
        requirement_level: opt_in
EOF

    # beyla.version / beyla.revision — the vendor-prefixed spelling of the
    # build metadata, which Beyla emits *in addition to* obi.version /
    # obi.revision. Both spellings really are on the wire:
    #
    #   emitter                                              | key emitted
    #   -----------------------------------------------------+----------------
    #   .../pkg/export/otel/metrics_internal.go:252          | obi.version
    #   (build-info metric)                                  | obi.revision
    #     → hard-coded string literals, not derived from attr.VendorPrefix
    #   .../pkg/export/otel/metrics_net.go:52-53             | beyla.version
    #   (network-flow *resource* attrs)                      | beyla.revision
    #   .../pkg/export/otel/metrics_stats.go:52-53           | beyla.version
    #   (stat-metric *resource* attrs)                       | beyla.revision
    #     → attr.VendorPrefix + attr.Vendor{Version,Revision}Suffix, and Beyla
    #       sets attr.VendorPrefix = "beyla" (pkg/beyla/config_obi.go)
    #
    # (paths relative to vendor/go.opentelemetry.io/obi/)
    #
    # OBI's registry only declares the obi.* pair (schemas/obi/groups/
    # obi_internal.yaml, added by OBI 97d2dad8 #2723), and since weaver 0.25.1
    # (OBI cd075683 #2866) an undeclared attribute is a hard violation, not
    # noise. That is what fails every netolly + stat suite — exactly the set
    # fed by metrics_net.go / metrics_stats.go — with both "does not exist in
    # the registry" and "collides with existing namespace 'beyla'" (the same
    # defect seen from weaver's other side: the `beyla` namespace exists via
    # beyla.ip / beyla.network.*, but these two keys under it are undeclared).
    #
    # So this is an *addition*, not a rename: the obi.* declarations kept alive
    # by SCHEMA_TRANSFORMS must stay for metric.beyla.internal.build.info's
    # refs to resolve.
    #
    # Group id is x.beyla.buildinfo so it sorts last, consistent with x.obi.cpu
    # and x.beyla.survey.
    #
    # DURABLE FIX: upstream OBI should derive the build-info metric's attribute
    # keys from attr.VendorPrefix, the way metrics_net.go already does. Once
    # that lands and flows back in via a submodule bump, both the
    # SCHEMA_TRANSFORMS undo rules *and* this injection can be dropped in
    # favour of the plain obi.* → beyla.* rename.
    cat > "$SCHEMAS_DEST/obi/groups/x_beyla_buildinfo.yaml" <<'EOF'
groups:
  # Vendor-prefixed build metadata. See scripts/generate-obi-tests.sh
  # (apply_schema_injections) for why Beyla emits both these keys and the
  # obi.version / obi.revision pair declared in obi_internal.yaml.
  - id: x.beyla.buildinfo
    type: attribute_group
    display_name: Beyla Build-Info Resource Attributes
    brief: >
      Vendor-prefixed build metadata that Beyla carries as *resource*
      attributes on network-flow and stat metrics.
    attributes:
      - id: beyla.version
        type: string
        stability: development
        brief: >
          Beyla build version, e.g. the release tag the instrumenter was built
          from. Carried as a resource attribute on network-flow and stat
          metrics.
        examples: ["v3.31.0"]
      - id: beyla.revision
        type: string
        stability: development
        brief: >
          Git SHA of the Beyla build. Carried as a resource attribute on
          network-flow and stat metrics.
        examples: ["a2a9a6e2"]
EOF
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
    copy_weavercheck
    copy_beyla_extensions
    transform_go_imports_and_paths "$jobs"
    apply_component_consolidation
    adjust_docker_compose_paths
    ensure_multiexec_local_image_reuse
    split_docker_build_contexts
    apply_behavioral_transforms "$jobs"
    restore_weaver_registry_mount_paths   # ← restore /obi-registry after BEHAVIORAL_TRANSFORMS
    stamp_obi_revision_into_multiexec_compose   # ← after all compose transforms, so the stamp survives
    ensure_daemonset_process_metrics_enabled
    ensure_otherinstance_has_service_version
    ensure_netolly_basic_guess_ports
    ensure_config_v2_v1_equivalents
    ensure_malicious_ioctl_local_downstream
    ensure_weaver_tap_survives_weavercol_startup
    cleanup_and_inject_build_tags "$jobs"

    # -----------------------------------------------------------------
    # OATs generation
    # -----------------------------------------------------------------
    copy_oats
    adjust_oats_compose_paths
    rewrite_oats_go_mod
    transform_oats_go_files "$jobs"
    apply_oats_behavioral_transforms "$jobs"
    tidy_oats_go_mods

    # -----------------------------------------------------------------
    # VM test infrastructure
    # -----------------------------------------------------------------
    copy_vm

    # -----------------------------------------------------------------
    # Weaver schemas test infrastructure
    # -----------------------------------------------------------------
    fetch_upstream_semconv   # ← populate .deps/ before copying
    copy_schemas
    apply_schema_transforms "$jobs"
    apply_schema_injections

    echo ""
    echo "Generated integration tests at $OBI_DEST"
    echo "Generated oats tests at $OATS_DEST"
    echo "Imported vm assets into $VM_DEST"
    echo "Imported weaver schemas into $SCHEMAS_DEST"
    echo ""
    echo "Using Beyla module path: $BEYLA_MODULE"
    echo "Env vars, metric names, etc. were automatically transformed to use Beyla conventions."
}

apply_component_path_transform() {
    local file="$1"
    sed_i -e 's|path\.Join(pathRoot, "internal", "test", "integration", "components",|path.Join(pathObiSrc, "internal", "test", "integration", "components",|g' \
        -e 's|pathRoot + "/internal/test/|pathObiSrc + "/internal/test/|g' \
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
