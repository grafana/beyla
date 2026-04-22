#!/usr/bin/env bash
#
# Downgrade in-scope modules in a release branch's go.mod to match the versions
# pinned in grafana/alloy's go.mod, so that Beyla/OBI release branches produce
# artifacts that can be embedded in Alloy without forcing OTel (or similar)
# upgrades.
#
# Scope (default):
#   - go.opentelemetry.io/*
#   - github.com/prometheus/*
#
# Rules, per in-scope module:
#   - If local version > Alloy version:  go get module@<alloy_version>
#   - If local version <= Alloy version: leave alone (MVS picks Alloy's version)
#   - If Alloy does not require the module: leave alone
#
# This script only mutates <repo-dir>.  It never pushes, never tags, and never
# touches mains of beyla, grafana/opentelemetry-ebpf-instrumentation, or
# open-telemetry/opentelemetry-ebpf-instrumentation.
#
# Invoked by scripts/release-train.sh after a release branch has been checked
# out.  Can also be run standalone for local dry-runs.

set -euo pipefail

REPO_DIR=""
ALLOY_REPO="grafana/alloy"
ALLOY_REF="main"
SCOPE_CSV="go.opentelemetry.io/*,github.com/prometheus/*"
SKIP_MODULES=("go.opentelemetry.io/obi")
DRY_RUN=false

OUTPUT_FILE="${ALIGN_OUTPUT_FILE:-}"

# Global scratch dir so the EXIT trap can clean up even after main() returns.
TMP_DIR=""
cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

log_info() {
    echo "[align] $*" >&2
}

log_warn() {
    echo "[align][warn] $*" >&2
}

log_error() {
    echo "[align][error] $*" >&2
}

die() {
    log_error "$*"
    exit 1
}

show_help() {
    cat << 'EOF'
Align a release branch's go.mod with grafana/alloy's go.mod.

Usage:
  ./scripts/align-with-alloy.sh --repo-dir <path> [options]

Required:
  --repo-dir <path>          Repo clone whose go.mod should be aligned.
                             Must already be checked out to the release branch.

Options:
  --alloy-repo <owner/repo>  Default: grafana/alloy
  --alloy-ref  <ref>         Branch, tag, or SHA. Default: main.
                             Resolved to a concrete SHA before download.
  --scope <csv>              Comma-separated module path globs to align.
                             Default: go.opentelemetry.io/*,github.com/prometheus/*
  --skip-module <module>     Repeatable. Always skipped:
                             go.opentelemetry.io/obi
  --dry-run                  Print the planned go get invocations without
                             modifying go.mod / go.sum / vendor.
  --help, -h                 Show this help.

Environment:
  ALIGN_OUTPUT_FILE          If set, writes:
                               alloy_sha=<resolved sha>
                               aligned_count=<n>
                               aligned_modules=<csv of module@old=>new>

Exit codes:
  0  success (even if no changes were needed)
  1  usage error or unrecoverable failure (network, parse, go get, etc.)
EOF
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo-dir=*)
            REPO_DIR="${1#*=}"
            shift
            ;;
        --repo-dir)
            [[ $# -ge 2 ]] || die "Option --repo-dir requires a value."
            REPO_DIR="$2"
            shift 2
            ;;
        --alloy-repo=*)
            ALLOY_REPO="${1#*=}"
            shift
            ;;
        --alloy-repo)
            [[ $# -ge 2 ]] || die "Option --alloy-repo requires a value."
            ALLOY_REPO="$2"
            shift 2
            ;;
        --alloy-ref=*)
            ALLOY_REF="${1#*=}"
            shift
            ;;
        --alloy-ref)
            [[ $# -ge 2 ]] || die "Option --alloy-ref requires a value."
            ALLOY_REF="$2"
            shift 2
            ;;
        --scope=*)
            SCOPE_CSV="${1#*=}"
            shift
            ;;
        --scope)
            [[ $# -ge 2 ]] || die "Option --scope requires a value."
            SCOPE_CSV="$2"
            shift 2
            ;;
        --skip-module=*)
            SKIP_MODULES+=("${1#*=}")
            shift
            ;;
        --skip-module)
            [[ $# -ge 2 ]] || die "Option --skip-module requires a value."
            SKIP_MODULES+=("$2")
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            die "Unknown option: $1"
            ;;
    esac
done

[[ -n "$REPO_DIR" ]] || { show_help; die "--repo-dir is required."; }
[[ -d "$REPO_DIR" ]] || die "--repo-dir does not exist: $REPO_DIR"
[[ -f "$REPO_DIR/go.mod" ]] || die "No go.mod in --repo-dir: $REPO_DIR"

require_cmd git
require_cmd curl
require_cmd awk
require_cmd go

# Prefer gh for SHA resolution if available; fall back to unauthenticated API.
resolve_alloy_sha() {
    local ref="$1"
    local sha=""

    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
        sha="$(gh api "repos/${ALLOY_REPO}/commits/${ref}" --jq '.sha' 2>/dev/null || true)"
    fi

    if [[ -z "$sha" ]]; then
        # Unauthenticated fallback; fine for public repos but rate-limited.
        local resp
        resp="$(curl -fsSL -H 'Accept: application/vnd.github+json' \
            "https://api.github.com/repos/${ALLOY_REPO}/commits/${ref}" 2>/dev/null || true)"
        if [[ -n "$resp" ]]; then
            sha="$(printf '%s' "$resp" | awk -F'"' '/"sha":[ ]*"/ { print $4; exit }')"
        fi
    fi

    [[ -n "$sha" ]] || die "Failed to resolve ${ALLOY_REPO}@${ref} to a SHA."
    printf '%s' "$sha"
}

download_alloy_go_mod() {
    local sha="$1"
    local dest="$2"
    local url="https://raw.githubusercontent.com/${ALLOY_REPO}/${sha}/go.mod"
    log_info "Downloading ${url}"
    curl -fsSL "$url" -o "$dest" || die "Failed to download Alloy go.mod at ${sha}"
    [[ -s "$dest" ]] || die "Downloaded Alloy go.mod is empty: ${url}"
}

# Print "module version" pairs from a go.mod's require blocks / require lines.
# Handles both:
#   require (
#       module v1.2.3
#       module v1.2.3 // indirect
#   )
#   require module v1.2.3
# Ignores replace/exclude/retract blocks entirely.
extract_requires() {
    local gomod="$1"
    awk '
        BEGIN { in_block = 0; block_kind = "" }
        /^[[:space:]]*\/\// { next }
        /^[[:space:]]*$/ { next }
        /^replace[[:space:]]*\(/    { in_block = 1; block_kind = "replace"; next }
        /^exclude[[:space:]]*\(/    { in_block = 1; block_kind = "exclude"; next }
        /^retract[[:space:]]*\(/    { in_block = 1; block_kind = "retract"; next }
        /^require[[:space:]]*\(/    { in_block = 1; block_kind = "require"; next }
        in_block && /^[[:space:]]*\)/ { in_block = 0; block_kind = ""; next }
        in_block && block_kind == "require" {
            line = $0
            sub(/\/\/.*$/, "", line)
            n = split(line, f, /[[:space:]]+/)
            mod = ""; ver = ""
            for (i = 1; i <= n; i++) {
                if (f[i] == "") continue
                if (mod == "") { mod = f[i]; continue }
                if (ver == "") { ver = f[i]; break }
            }
            if (mod != "" && ver != "") print mod, ver
            next
        }
        /^require[[:space:]]+[^(]/ {
            line = $0
            sub(/^require[[:space:]]+/, "", line)
            sub(/\/\/.*$/, "", line)
            n = split(line, f, /[[:space:]]+/)
            mod = ""; ver = ""
            for (i = 1; i <= n; i++) {
                if (f[i] == "") continue
                if (mod == "") { mod = f[i]; continue }
                if (ver == "") { ver = f[i]; break }
            }
            if (mod != "" && ver != "") print mod, ver
            next
        }
    ' "$gomod"
}

matches_scope() {
    local mod="$1"
    local csv="$2"
    local IFS=','
    local pattern
    # shellcheck disable=SC2206
    local patterns=($csv)
    for pattern in "${patterns[@]}"; do
        [[ -z "$pattern" ]] && continue
        # Glob match: go.opentelemetry.io/* etc.
        # shellcheck disable=SC2053
        [[ "$mod" == $pattern ]] && return 0
    done
    return 1
}

is_skipped() {
    local mod="$1"
    local skip
    for skip in "${SKIP_MODULES[@]}"; do
        [[ "$mod" == "$skip" ]] && return 0
    done
    return 1
}

# Compare two semver-ish Go module versions.
# Prints: ">" if a > b, "<" if a < b, "=" if equal.
# Uses sort -V which handles pseudo-versions well enough for our purposes.
compare_versions() {
    local a="$1"
    local b="$2"
    if [[ "$a" == "$b" ]]; then
        printf '='
        return
    fi
    local higher
    higher="$(printf '%s\n%s\n' "$a" "$b" | sort -V | tail -n 1)"
    if [[ "$higher" == "$a" ]]; then
        printf '>'
    else
        printf '<'
    fi
}

write_output() {
    local key="$1"
    local value="$2"
    if [[ -n "$OUTPUT_FILE" ]]; then
        printf '%s=%s\n' "$key" "$value" >> "$OUTPUT_FILE"
    fi
}

main() {
    local alloy_sha
    alloy_sha="$(resolve_alloy_sha "$ALLOY_REF")"
    log_info "Resolved ${ALLOY_REPO}@${ALLOY_REF} -> ${alloy_sha}"

    TMP_DIR="$(mktemp -d -t align-with-alloy.XXXXXX)"

    local alloy_gomod="${TMP_DIR}/alloy.go.mod"
    download_alloy_go_mod "$alloy_sha" "$alloy_gomod"

    local alloy_reqs="${TMP_DIR}/alloy.requires"
    local local_reqs="${TMP_DIR}/local.requires"
    extract_requires "$alloy_gomod" | LC_ALL=C sort -u > "$alloy_reqs"
    extract_requires "${REPO_DIR}/go.mod" | LC_ALL=C sort -u > "$local_reqs"

    local alloy_count local_count
    alloy_count="$(wc -l < "$alloy_reqs" | tr -d ' ')"
    local_count="$(wc -l < "$local_reqs" | tr -d ' ')"
    log_info "Alloy requires ${alloy_count} modules; local requires ${local_count}."

    # Build an associative array: alloy[module] = version.
    declare -A alloy_ver
    while read -r mod ver; do
        [[ -z "$mod" ]] && continue
        alloy_ver["$mod"]="$ver"
    done < "$alloy_reqs"

    local -a plan_mods=()
    local -a plan_old=()
    local -a plan_new=()
    local in_scope_total=0
    local already_ok=0

    while read -r mod local_version; do
        [[ -z "$mod" ]] && continue
        matches_scope "$mod" "$SCOPE_CSV" || continue
        is_skipped "$mod" && { log_info "Skipping (skip-list): ${mod}"; continue; }

        in_scope_total=$((in_scope_total + 1))

        local alloy_version="${alloy_ver[$mod]:-}"
        if [[ -z "$alloy_version" ]]; then
            log_info "In scope but not required by Alloy, leaving alone: ${mod}@${local_version}"
            continue
        fi

        local cmp
        cmp="$(compare_versions "$local_version" "$alloy_version")"
        case "$cmp" in
            '=')
                already_ok=$((already_ok + 1))
                ;;
            '<')
                log_info "Local already <= Alloy (MVS will pick Alloy's): ${mod} local=${local_version} alloy=${alloy_version}"
                already_ok=$((already_ok + 1))
                ;;
            '>')
                plan_mods+=("$mod")
                plan_old+=("$local_version")
                plan_new+=("$alloy_version")
                ;;
        esac
    done < "$local_reqs"

    log_info "In-scope local modules: ${in_scope_total}; already aligned or lower: ${already_ok}; to downgrade: ${#plan_mods[@]}"

    local aligned_csv=""
    local aligned_count=0

    if [[ "${#plan_mods[@]}" -eq 0 ]]; then
        log_info "No downgrades needed. Release branch is already aligned with grafana/alloy@${alloy_sha:0:12}."
    else
        printf '[align] plan:\n' >&2
        local i
        for ((i = 0; i < ${#plan_mods[@]}; i++)); do
            printf '[align]   %s  %s -> %s\n' "${plan_mods[$i]}" "${plan_old[$i]}" "${plan_new[$i]}" >&2
        done

        if [[ "$DRY_RUN" == "true" ]]; then
            log_warn "Dry-run: not invoking 'go get' or 'go mod tidy'."
        else
            # One go get invocation per module keeps the logs readable and lets us
            # surface which specific pin broke if a downgrade fails.
            local idx
            for ((idx = 0; idx < ${#plan_mods[@]}; idx++)); do
                local mod="${plan_mods[$idx]}"
                local ver="${plan_new[$idx]}"
                log_info "go get ${mod}@${ver}"
                ( cd "$REPO_DIR" && GOFLAGS='' go get "${mod}@${ver}" ) \
                    || die "go get ${mod}@${ver} failed in ${REPO_DIR}"
            done

            log_info "go mod tidy"
            ( cd "$REPO_DIR" && GOFLAGS='' go mod tidy ) || die "go mod tidy failed in ${REPO_DIR}"

            if [[ -d "${REPO_DIR}/vendor" ]]; then
                log_info "go mod vendor"
                ( cd "$REPO_DIR" && GOFLAGS='' go mod vendor ) || die "go mod vendor failed in ${REPO_DIR}"
            fi
        fi

        aligned_count="${#plan_mods[@]}"
        local sep=""
        for ((i = 0; i < ${#plan_mods[@]}; i++)); do
            aligned_csv+="${sep}${plan_mods[$i]}@${plan_old[$i]}=>${plan_new[$i]}"
            sep=","
        done
    fi

    write_output "alloy_sha" "$alloy_sha"
    write_output "aligned_count" "$aligned_count"
    write_output "aligned_modules" "$aligned_csv"

    log_info "Done. alloy_sha=${alloy_sha} aligned_count=${aligned_count}"
}

main "$@"
