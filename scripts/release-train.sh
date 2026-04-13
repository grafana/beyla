#!/usr/bin/env bash
#
# Automate the Beyla/OBI release train workflow.
#
# Commands:
#   prepare  - Cut/update release branches in OBI and Beyla
#   tag      - Create tags and prereleases in OBI and Beyla
#
# Notes:
#   - Versions must be SemVer tags: vMAJOR.MINOR.PATCH
#   - Release branch naming is: release-MAJOR.MINOR.PATCH (no "v" prefix)
#   - Run from any directory (the script uses temporary clones)

set -euo pipefail

BEYLA_REPO="grafana/beyla"
OBI_REPO="grafana/opentelemetry-ebpf-instrumentation"
UPSTREAM_OBI_REPO="open-telemetry/opentelemetry-ebpf-instrumentation"
BEYLA_MAIN_BRANCH="main"
OBI_MAIN_BRANCH="main"

COMMAND=""
BEYLA_VERSION=""
OBI_VERSION=""
BUMP_MODE="auto"
DRY_RUN=false
SKIP_CI_CHECK=false
SKIP_UPSTREAM_SYNC_CHECK=false
EXCLUDE_CHECK_NAME=""
WORKDIR=""

RELEASE_TRAIN_TOKEN="${RELEASE_TRAIN_TOKEN:-${GITHUB_TOKEN:-${GH_TOKEN:-}}}"
OUTPUT_FILE="${RELEASE_TRAIN_OUTPUT_FILE:-}"

WORKSPACE=""
WORKSPACE_AUTO_CREATED=false
BEYLA_DIR=""
OBI_DIR=""

DATE_BIN=""

log_info() {
    echo "[info] $*" >&2
}

log_warn() {
    echo "[warn] $*" >&2
}

log_error() {
    echo "[error] $*" >&2
}

die() {
    log_error "$*"
    exit 1
}

show_help() {
    cat << 'EOF'
Automate the Beyla/OBI release train workflow

Usage:
  ./scripts/release-train.sh <command> [options]

Commands:
  prepare                 Cut/update OBI+Beyla release branches
  tag                     Tag OBI+Beyla and create prereleases

Common options:
  --beyla-version <vX.Y.Z>
  --obi-version <vX.Y.Z>
  --beyla-repo <owner/repo>
  --obi-repo <owner/repo>
  --dry-run               Validate and print actions, without pushing/tags/releases
  --skip-ci-check         Skip CI-green checks (main for prepare, release branch for tag)
  --exclude-check <name>  Exclude a check-run by name (e.g. the calling job itself)
  --workdir <path>        Reuse a workspace directory (default: temporary directory)
  --help, -h              Show this help message

Prepare-only options:
  --bump <auto|minor|patch>
                          auto  -> weekly rule: bump MINOR unless latest tag is from this week, then bump PATCH
                          minor -> force MINOR bump
                          patch -> force PATCH bump
  --skip-upstream-sync-check
                          Skip verification that grafana OBI main includes upstream OBI main

Examples:
  # Auto compute the next release versions and cut release branches
  ./scripts/release-train.sh prepare

  # Force specific versions
  ./scripts/release-train.sh prepare --beyla-version v4.3.0 --obi-version v1.0.0

  # After CI is green, create tags and prereleases
  ./scripts/release-train.sh tag --beyla-version v4.3.0 --obi-version v1.0.0
EOF
}

run_cmd() {
    log_info "+ $*"
    "$@"
}

run_git_remote_cmd() {
    if [[ -n "$RELEASE_TRAIN_TOKEN" ]]; then
        local auth_b64
        auth_b64="$(printf 'x-access-token:%s' "$RELEASE_TRAIN_TOKEN" | base64 | tr -d '\n')"
        log_info "+ git [auth] $*"
        git -c "http.https://github.com/.extraheader=Authorization: Basic ${auth_b64}" "$@"
        return
    fi

    run_cmd git "$@"
}

run_write_cmd() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[dry-run] $*"
        return 0
    fi
    run_cmd "$@"
}

run_write_git_remote_cmd() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[dry-run] git $*"
        return 0
    fi

    run_git_remote_cmd "$@"
}

require_cmd() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
}

ensure_gh_auth() {
    require_cmd gh
    if gh auth status >/dev/null 2>&1; then
        return
    fi
    if [[ -n "${GH_TOKEN:-}" ]] && gh api rate_limit >/dev/null 2>&1; then
        return
    fi
    die "gh CLI is not authenticated. Run 'gh auth login' first or set GH_TOKEN."
}

set_output() {
    local key="$1"
    local value="$2"
    if [[ -n "$OUTPUT_FILE" ]]; then
        printf "%s=%s\n" "$key" "$value" >> "$OUTPUT_FILE"
    fi
}

validate_semver_tag() {
    local tag="$1"
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Invalid SemVer tag: $tag (expected vMAJOR.MINOR.PATCH)"
}

version_without_v() {
    local tag="$1"
    echo "${tag#v}"
}

parse_semver() {
    local tag="$1"
    local parsed="${tag#v}"
    local major minor patch
    IFS='.' read -r major minor patch <<< "$parsed"
    [[ -n "$major" && -n "$minor" && -n "$patch" ]] || die "Could not parse SemVer tag: $tag"
    printf "%s %s %s" "$major" "$minor" "$patch"
}

select_date_bin() {
    if date -u -d "@0" +%s >/dev/null 2>&1; then
        DATE_BIN="date"
        return
    fi
    if command -v gdate >/dev/null 2>&1 && gdate -u -d "@0" +%s >/dev/null 2>&1; then
        DATE_BIN="gdate"
        return
    fi
    die "GNU date is required (date or gdate) to compute weekly version bumps."
}

week_start_epoch_utc() {
    local weekday days_back
    weekday=$("$DATE_BIN" -u +%u)
    days_back=$((weekday - 1))
    "$DATE_BIN" -u -d "-${days_back} days 00:00:00" +%s
}

setup_workspace() {
    if [[ -n "$WORKDIR" ]]; then
        mkdir -p "$WORKDIR"
        WORKSPACE="$WORKDIR"
        WORKSPACE_AUTO_CREATED=false
    else
        WORKSPACE="$(mktemp -d -t release-train.XXXXXX)"
        WORKSPACE_AUTO_CREATED=true
    fi

    BEYLA_DIR="${WORKSPACE}/beyla"
    OBI_DIR="${WORKSPACE}/obi"
    log_info "Workspace: ${WORKSPACE}"
}

cleanup_workspace() {
    if [[ "$WORKSPACE_AUTO_CREATED" == "true" && -n "$WORKSPACE" ]]; then
        rm -rf "$WORKSPACE"
    fi
}

trap cleanup_workspace EXIT

normalize_origin_remote() {
    local repo_dir="$1"
    local repo_slug="$2"

    local desired_url="https://github.com/${repo_slug}.git"
    local current_url
    current_url="$(git -C "$repo_dir" remote get-url origin)"
    if [[ "$current_url" == "$desired_url" ]]; then
        return
    fi

    run_cmd git -C "$repo_dir" remote set-url origin "$desired_url"
}

clone_repo() {
    local repo_slug="$1"
    local target_dir="$2"

    if [[ -d "$target_dir/.git" ]]; then
        normalize_origin_remote "$target_dir" "$repo_slug"
    else
        run_git_remote_cmd clone "https://github.com/${repo_slug}.git" "$target_dir"
    fi

    run_git_remote_cmd -C "$target_dir" fetch --prune --tags origin
}

set_git_identity() {
    local repo_dir="$1"
    run_cmd git -C "$repo_dir" config user.name "github-actions[bot]"
    run_cmd git -C "$repo_dir" config user.email "github-actions[bot]@users.noreply.github.com"
}

check_ci_green() {
    local repo_slug="$1"
    local ref="$2"
    local label="$3"
    local exclude_check_name="${4:-}"

    require_cmd jq

    local sha
    if ! sha=$(gh api "repos/${repo_slug}/commits/${ref}" --jq '.sha' 2>&1); then
        die "Failed to resolve ${repo_slug}@${ref}: ${sha}. If this is a local dry-run without org access, use --skip-ci-check."
    fi

    log_info "Checking CI for ${label} (${sha:0:12})"

    # Build a set of check-suite IDs from push-triggered workflow runs.
    # The commit may also have check-runs from schedule or workflow_dispatch
    # triggered suites (e.g. cron jobs, release workflows) which are not part
    # of the commit's push CI and should be excluded — matching GitHub UI behavior.
    local push_suite_ids
    push_suite_ids=$(
        gh api --paginate -H "Accept: application/vnd.github+json" \
            "repos/${repo_slug}/actions/runs?head_sha=${sha}&event=push&per_page=100" \
            | jq -s '[ map(.workflow_runs // []) | add // [] | .[].check_suite_id ]'
    )

    # Fetch all check-runs once, then filter and deduplicate.
    local all_checks_json
    all_checks_json=$(
        gh api --paginate -H "Accept: application/vnd.github+json" \
            "repos/${repo_slug}/commits/${sha}/check-runs?per_page=100" \
            | jq -s '{check_runs: ((map(.check_runs // []) | add) // [])}'
    )

    # Keep only check-runs from push-triggered suites or from non-Actions apps
    # (e.g. socket-security, codecov).  Then deduplicate by name keeping the
    # most recent entry (highest .id), matching GitHub's UI behavior.
    local checks_json
    checks_json=$(jq --argjson push_suites "$push_suite_ids" \
        '{check_runs: [.check_runs[] | select(
            .app.slug != "github-actions" or
            (.check_suite.id as $id | $push_suites | index($id))
        )]}' <<< "$all_checks_json" \
        | jq '{check_runs: [.check_runs | group_by(.name) | .[] | sort_by(.id) | last]}')

    if [[ -n "$exclude_check_name" ]]; then
        log_info "Excluding self check-run: ${exclude_check_name}"
        checks_json=$(jq --arg name "$exclude_check_name" \
            '{check_runs: [.check_runs[] | select(.name != $name)]}' <<< "$checks_json")
    fi

    local total_checks
    total_checks=$(jq -r '.check_runs | length' <<< "$checks_json")

    if [[ "$total_checks" != "0" ]]; then
        local non_green_count
        non_green_count=$(
            jq -r '[.check_runs[] | select(.status != "completed" or (.conclusion != "success" and .conclusion != "neutral" and .conclusion != "skipped"))] | length' \
                <<< "$checks_json"
        )

        if [[ "$non_green_count" != "0" ]]; then
            jq -r '.check_runs[]
                | select(.status != "completed" or (.conclusion != "success" and .conclusion != "neutral" and .conclusion != "skipped"))
                | "- \(.name): status=\(.status), conclusion=\(.conclusion // "none")"' <<< "$checks_json" >&2
            die "CI is not green for ${label}"
        fi

        log_info "CI is green for ${label}"
        return
    fi

    # Fallback for repositories that only publish legacy commit statuses.
    local status_state
    status_state=$(gh api "repos/${repo_slug}/commits/${sha}/status" --jq '.state')
    if [[ "$status_state" != "success" ]]; then
        die "Commit status is ${status_state} for ${label}"
    fi

    log_warn "No check-runs found for ${label}; legacy commit status is success."
}

check_obi_fork_sync() {
    if git -C "$OBI_DIR" remote get-url upstream >/dev/null 2>&1; then
        :
    else
        run_cmd git -C "$OBI_DIR" remote add upstream "https://github.com/${UPSTREAM_OBI_REPO}.git"
    fi

    if ! run_git_remote_cmd -C "$OBI_DIR" fetch upstream "$OBI_MAIN_BRANCH"; then
        log_warn "Could not fetch ${UPSTREAM_OBI_REPO}:${OBI_MAIN_BRANCH}; skipping informational sync check."
        return
    fi

    if git -C "$OBI_DIR" merge-base --is-ancestor "upstream/${OBI_MAIN_BRANCH}" "origin/${OBI_MAIN_BRANCH}"; then
        log_info "OBI fork main contains upstream/${OBI_MAIN_BRANCH}"
        return
    fi

    log_warn "OBI fork ${OBI_REPO}:${OBI_MAIN_BRANCH} is behind ${UPSTREAM_OBI_REPO}:${OBI_MAIN_BRANCH}; release will still use the OBI SHA pinned in ${BEYLA_REPO}:${BEYLA_MAIN_BRANCH}."
}

resolve_obi_sha_from_beyla_main() {
    local tree_line
    tree_line=$(git -C "$BEYLA_DIR" ls-tree "origin/${BEYLA_MAIN_BRANCH}" .obi-src) || {
        die "Failed to inspect .obi-src in ${BEYLA_REPO}:${BEYLA_MAIN_BRANCH}"
    }

    local obi_sha
    obi_sha=$(awk '{print $3}' <<< "$tree_line")
    [[ -n "$obi_sha" ]] || die "Could not determine .obi-src SHA from ${BEYLA_REPO}:${BEYLA_MAIN_BRANCH}"
    echo "$obi_sha"
}

latest_semver_tag_from_repo() {
    local repo_dir="$1"
    git -C "$repo_dir" tag --list 'v[0-9]*.[0-9]*.[0-9]*' \
        | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
        | sort -V \
        | tail -n 1
}

tag_epoch_from_repo() {
    local repo_dir="$1"
    local tag="$2"
    git -C "$repo_dir" for-each-ref --format='%(creatordate:unix)' "refs/tags/${tag}" | head -n 1
}

auto_compute_next_version() {
    local repo_dir="$1"
    local repo_slug="$2"

    local latest_tag
    latest_tag="$(latest_semver_tag_from_repo "$repo_dir")"
    [[ -n "$latest_tag" ]] || die "Could not auto-compute version for ${repo_slug}: no SemVer tags found. Use --beyla-version or --obi-version."

    validate_semver_tag "$latest_tag"

    local major minor patch
    read -r major minor patch <<< "$(parse_semver "$latest_tag")"

    local effective_bump="$BUMP_MODE"
    case "$effective_bump" in
        auto)
            select_date_bin
            local latest_epoch week_epoch
            latest_epoch="$(tag_epoch_from_repo "$repo_dir" "$latest_tag")"
            week_epoch="$(week_start_epoch_utc)"
            if [[ -z "$latest_epoch" ]]; then
                die "Could not determine timestamp for latest tag ${latest_tag} in ${repo_slug}"
            fi
            if (( latest_epoch >= week_epoch )); then
                effective_bump="patch"
            else
                effective_bump="minor"
            fi
            ;;
        minor|patch)
            ;;
        *)
            die "Invalid --bump value: ${BUMP_MODE}. Use auto, minor, or patch."
            ;;
    esac

    case "$effective_bump" in
        minor)
            minor=$((minor + 1))
            patch=0
            ;;
        patch)
            patch=$((patch + 1))
            ;;
        *)
            die "Unexpected bump mode: ${effective_bump}"
            ;;
    esac

    printf "v%s.%s.%s" "$major" "$minor" "$patch"
}

resolve_prepare_versions() {
    if [[ -n "$BEYLA_VERSION" ]]; then
        validate_semver_tag "$BEYLA_VERSION"
        log_info "Using explicit Beyla version: ${BEYLA_VERSION}"
    else
        BEYLA_VERSION="$(auto_compute_next_version "$BEYLA_DIR" "$BEYLA_REPO")"
        log_info "Auto-computed Beyla version: ${BEYLA_VERSION}"
    fi

    if [[ -n "$OBI_VERSION" ]]; then
        validate_semver_tag "$OBI_VERSION"
        log_info "Using explicit OBI version: ${OBI_VERSION}"
    else
        OBI_VERSION="$(auto_compute_next_version "$OBI_DIR" "$OBI_REPO")"
        log_info "Auto-computed OBI version: ${OBI_VERSION}"
    fi
}

resolve_tag_versions() {
    [[ -n "$BEYLA_VERSION" ]] || die "--beyla-version is required for the tag command."
    [[ -n "$OBI_VERSION" ]] || die "--obi-version is required for the tag command."

    validate_semver_tag "$BEYLA_VERSION"
    validate_semver_tag "$OBI_VERSION"
}

checkout_or_create_release_branch() {
    local repo_dir="$1"
    local base_branch="$2"
    local release_branch="$3"

    run_git_remote_cmd -C "$repo_dir" fetch --prune origin

    if git -C "$repo_dir" show-ref --verify --quiet "refs/remotes/origin/${release_branch}"; then
        run_cmd git -C "$repo_dir" checkout -B "$release_branch" "origin/${release_branch}"
    else
        run_cmd git -C "$repo_dir" checkout -B "$release_branch" "origin/${base_branch}"
    fi
}

uncomment_bpfel_in_gitignore() {
    local repo_dir="$1"
    local gitignore="${repo_dir}/.gitignore"

    if [[ ! -f "$gitignore" ]]; then
        log_warn "No .gitignore found in ${repo_dir}; skipping bpfel uncomment."
        return
    fi

    if ! grep -q '^\*_bpfel\.' "$gitignore"; then
        log_info "No active bpfel gitignore rules found in ${repo_dir}; skipping."
        return
    fi

    log_info "Commenting out bpfel exclusions in ${gitignore} for release branch"
    sed -i.bak \
        -e 's/^\(\*_bpfel\.go\)$/#\1/' \
        -e 's/^\(\*_bpfel\.o\)$/#\1/' \
        -e 's/^\(\*_bpfel\.go\.d\)$/#\1/' \
        "$gitignore"
    rm -f "${gitignore}.bak"
}

prepare_obi_branch() {
    local version="$1"
    local release_branch="$2"
    local obi_sha="$3"

    run_git_remote_cmd -C "$OBI_DIR" fetch --prune origin

    if git -C "$OBI_DIR" show-ref --verify --quiet "refs/remotes/origin/${release_branch}"; then
        log_info "OBI branch ${release_branch} already exists; reusing it."
        run_cmd git -C "$OBI_DIR" checkout -B "$release_branch" "origin/${release_branch}"
        if ! git -C "$OBI_DIR" merge-base --is-ancestor "$obi_sha" HEAD; then
            die "Existing OBI branch ${release_branch} does not contain pinned SHA ${obi_sha}"
        fi
    else
        run_cmd git -C "$OBI_DIR" checkout "$obi_sha"
        run_cmd git -C "$OBI_DIR" checkout -B "$release_branch"
    fi

    uncomment_bpfel_in_gitignore "$OBI_DIR"

    run_write_cmd make -C "$OBI_DIR" docker-generate
    run_write_cmd make -C "$OBI_DIR" java-build

    run_write_cmd git -C "$OBI_DIR" add -A
    if ! git -C "$OBI_DIR" diff --cached --quiet; then
        run_write_cmd git -C "$OBI_DIR" commit -m "Release ${version} artifacts"
    else
        log_info "No OBI artifact changes to commit."
    fi

    run_write_git_remote_cmd -C "$OBI_DIR" push -u origin "$release_branch"
}

prepare_beyla_branch() {
    local version="$1"
    local release_branch="$2"
    local obi_sha="$3"

    checkout_or_create_release_branch "$BEYLA_DIR" "$BEYLA_MAIN_BRANCH" "$release_branch"

    run_cmd git -C "$BEYLA_DIR" submodule sync --recursive
    run_cmd git -C "$BEYLA_DIR" submodule update --init --recursive

    run_git_remote_cmd -C "$BEYLA_DIR/.obi-src" fetch --prune origin
    run_cmd git -C "$BEYLA_DIR/.obi-src" checkout "$obi_sha"

    run_write_cmd git -C "$BEYLA_DIR" add .obi-src
    if ! git -C "$BEYLA_DIR" diff --cached --quiet; then
        run_write_cmd git -C "$BEYLA_DIR" commit -m "Update obi submodule (${version})"
    else
        log_info "No Beyla submodule pointer change to commit."
    fi

    uncomment_bpfel_in_gitignore "$BEYLA_DIR"

    run_write_cmd make -C "$BEYLA_DIR" vendor-obi
    run_write_cmd make -C "$BEYLA_DIR" java-build

    run_write_cmd git -C "$BEYLA_DIR" add -A
    if ! git -C "$BEYLA_DIR" diff --cached --quiet; then
        run_write_cmd git -C "$BEYLA_DIR" commit -m "Release ${version} artifacts"
    else
        log_info "No Beyla release artifact changes to commit."
    fi

    run_write_git_remote_cmd -C "$BEYLA_DIR" push -u origin "$release_branch"
}

ensure_release_branch_exists() {
    local repo_dir="$1"
    local repo_slug="$2"
    local release_branch="$3"

    run_git_remote_cmd -C "$repo_dir" fetch --prune --tags origin
    if ! git -C "$repo_dir" show-ref --verify --quiet "refs/remotes/origin/${release_branch}"; then
        die "Branch ${release_branch} not found in ${repo_slug}"
    fi
    run_cmd git -C "$repo_dir" checkout -B "$release_branch" "origin/${release_branch}"
}

ensure_tag_on_sha() {
    local repo_dir="$1"
    local repo_slug="$2"
    local version="$3"
    local target_sha="$4"

    if ! git -C "$repo_dir" cat-file -e "${target_sha}^{commit}" >/dev/null 2>&1; then
        die "Target commit ${target_sha} does not exist in ${repo_slug} local clone."
    fi

    local tag_created=false
    if git -C "$repo_dir" rev-parse -q --verify "refs/tags/${version}" >/dev/null; then
        local existing_sha
        existing_sha=$(git -C "$repo_dir" rev-list -n 1 "${version}")
        if [[ "$existing_sha" != "$target_sha" ]]; then
            die "Tag ${version} in ${repo_slug} points to ${existing_sha}, expected ${target_sha}."
        fi
        log_info "Tag ${version} already exists in ${repo_slug} at the expected commit."
    else
        run_write_cmd git -C "$repo_dir" tag "$version" "$target_sha"
        tag_created=true
    fi

    if [[ "$tag_created" == "true" ]]; then
        run_write_git_remote_cmd -C "$repo_dir" push origin "refs/tags/${version}"
    fi

    echo "$target_sha"
}

ensure_prerelease_exists() {
    local repo_slug="$1"
    local version="$2"
    local target_sha="$3"
    local notes="$4"

    if gh release view "$version" --repo "$repo_slug" >/dev/null 2>&1; then
        local is_prerelease
        is_prerelease=$(gh release view "$version" --repo "$repo_slug" --json isPrerelease --jq '.isPrerelease')
        if [[ "$is_prerelease" != "true" ]]; then
            die "Release ${repo_slug}@${version} already exists and is not a pre-release."
        fi
        log_info "Pre-release ${repo_slug}@${version} already exists."
        return
    fi

    run_write_cmd gh release create "$version" \
        --repo "$repo_slug" \
        --target "$target_sha" \
        --title "$version" \
        --prerelease \
        --notes "$notes"
}

prepare_command() {
    require_cmd git
    require_cmd gh
    require_cmd jq
    require_cmd make
    ensure_gh_auth

    setup_workspace

    clone_repo "$BEYLA_REPO" "$BEYLA_DIR"
    clone_repo "$OBI_REPO" "$OBI_DIR"
    set_git_identity "$BEYLA_DIR"
    set_git_identity "$OBI_DIR"

    run_cmd git -C "$BEYLA_DIR" checkout -B "$BEYLA_MAIN_BRANCH" "origin/${BEYLA_MAIN_BRANCH}"
    run_cmd git -C "$OBI_DIR" checkout -B "$OBI_MAIN_BRANCH" "origin/${OBI_MAIN_BRANCH}"

    if [[ "$SKIP_CI_CHECK" == "true" ]]; then
        log_warn "Skipping CI check for ${BEYLA_REPO}:${BEYLA_MAIN_BRANCH}"
    else
        check_ci_green "$BEYLA_REPO" "$BEYLA_MAIN_BRANCH" "${BEYLA_REPO}:${BEYLA_MAIN_BRANCH}" "$EXCLUDE_CHECK_NAME"
    fi

    if [[ "$SKIP_UPSTREAM_SYNC_CHECK" == "true" ]]; then
        log_warn "Skipping OBI upstream sync check."
    else
        check_obi_fork_sync
    fi

    local obi_sha
    obi_sha="$(resolve_obi_sha_from_beyla_main)"
    log_info "OBI SHA pinned in ${BEYLA_REPO}:${BEYLA_MAIN_BRANCH}: ${obi_sha}"

    resolve_prepare_versions
    local beyla_release_branch="release-$(version_without_v "$BEYLA_VERSION")"
    local obi_release_branch="release-$(version_without_v "$OBI_VERSION")"

    prepare_obi_branch "$OBI_VERSION" "$obi_release_branch" "$obi_sha"
    local obi_release_sha
    obi_release_sha="$(git -C "$OBI_DIR" rev-parse HEAD)"
    log_info "OBI release branch tip SHA: ${obi_release_sha}"
    prepare_beyla_branch "$BEYLA_VERSION" "$beyla_release_branch" "$obi_release_sha"

    log_info "Release branches prepared: beyla_version=${BEYLA_VERSION}, beyla_branch=${beyla_release_branch}, obi_version=${OBI_VERSION}, obi_branch=${obi_release_branch}"

    set_output "version" "$BEYLA_VERSION"
    set_output "release_branch" "$beyla_release_branch"
    set_output "beyla_version" "$BEYLA_VERSION"
    set_output "obi_version" "$OBI_VERSION"
    set_output "beyla_release_branch" "$beyla_release_branch"
    set_output "obi_release_branch" "$obi_release_branch"
    set_output "obi_sha" "$obi_sha"
    set_output "beyla_repo" "$BEYLA_REPO"
    set_output "obi_repo" "$OBI_REPO"
}

tag_command() {
    require_cmd git
    require_cmd gh
    require_cmd jq
    ensure_gh_auth

    resolve_tag_versions
    local beyla_release_branch="release-$(version_without_v "$BEYLA_VERSION")"
    local obi_release_branch="release-$(version_without_v "$OBI_VERSION")"

    setup_workspace

    clone_repo "$BEYLA_REPO" "$BEYLA_DIR"
    clone_repo "$OBI_REPO" "$OBI_DIR"
    set_git_identity "$BEYLA_DIR"
    set_git_identity "$OBI_DIR"

    ensure_release_branch_exists "$OBI_DIR" "$OBI_REPO" "$obi_release_branch"
    local obi_checked_sha
    obi_checked_sha=$(git -C "$OBI_DIR" rev-parse "origin/${obi_release_branch}")

    ensure_release_branch_exists "$BEYLA_DIR" "$BEYLA_REPO" "$beyla_release_branch"
    local beyla_checked_sha
    beyla_checked_sha=$(git -C "$BEYLA_DIR" rev-parse "origin/${beyla_release_branch}")

    if [[ "$SKIP_CI_CHECK" == "true" ]]; then
        log_warn "Skipping CI checks for release branches."
    else
        check_ci_green "$OBI_REPO" "$obi_checked_sha" "${OBI_REPO}:${obi_release_branch}@${obi_checked_sha:0:12}" "$EXCLUDE_CHECK_NAME"
        check_ci_green "$BEYLA_REPO" "$beyla_checked_sha" "${BEYLA_REPO}:${beyla_release_branch}@${beyla_checked_sha:0:12}" "$EXCLUDE_CHECK_NAME"
    fi

    local obi_target_sha
    obi_target_sha="$(ensure_tag_on_sha "$OBI_DIR" "$OBI_REPO" "$OBI_VERSION" "$obi_checked_sha")"
    ensure_prerelease_exists "$OBI_REPO" "$OBI_VERSION" "$obi_target_sha" "Release train candidate ${OBI_VERSION}"

    local beyla_target_sha
    beyla_target_sha="$(ensure_tag_on_sha "$BEYLA_DIR" "$BEYLA_REPO" "$BEYLA_VERSION" "$beyla_checked_sha")"
    ensure_prerelease_exists "$BEYLA_REPO" "$BEYLA_VERSION" "$beyla_target_sha" "Release train candidate ${BEYLA_VERSION}"

    log_info "Release tags and prereleases prepared: beyla_version=${BEYLA_VERSION}, obi_version=${OBI_VERSION}"

    set_output "version" "$BEYLA_VERSION"
    set_output "release_branch" "$beyla_release_branch"
    set_output "beyla_version" "$BEYLA_VERSION"
    set_output "obi_version" "$OBI_VERSION"
    set_output "beyla_release_branch" "$beyla_release_branch"
    set_output "obi_release_branch" "$obi_release_branch"
    set_output "beyla_target_sha" "$beyla_target_sha"
    set_output "obi_target_sha" "$obi_target_sha"
}

parse_args() {
    if [[ $# -eq 0 ]]; then
        show_help
        exit 1
    fi

    COMMAND="$1"
    shift

    case "$COMMAND" in
        prepare|tag)
            ;;
        --help|-h|help)
            show_help
            exit 0
            ;;
        *)
            die "Unknown command: ${COMMAND}"
            ;;
    esac

    require_option_value() {
        local opt_name="$1"
        local opt_value="${2:-}"
        if [[ $# -lt 2 || -z "$opt_value" ]]; then
            die "Option ${opt_name} requires a value."
        fi
    }

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --beyla-version=*)
                BEYLA_VERSION="${1#*=}"
                shift
                ;;
            --beyla-version)
                require_option_value "$1" "${2:-}"
                BEYLA_VERSION="${2:-}"
                shift 2
                ;;
            --obi-version=*)
                OBI_VERSION="${1#*=}"
                shift
                ;;
            --obi-version)
                require_option_value "$1" "${2:-}"
                OBI_VERSION="${2:-}"
                shift 2
                ;;
            --bump=*)
                BUMP_MODE="${1#*=}"
                shift
                ;;
            --bump)
                require_option_value "$1" "${2:-}"
                BUMP_MODE="${2:-}"
                shift 2
                ;;
            --beyla-repo=*)
                BEYLA_REPO="${1#*=}"
                shift
                ;;
            --beyla-repo)
                require_option_value "$1" "${2:-}"
                BEYLA_REPO="${2:-}"
                shift 2
                ;;
            --obi-repo=*)
                OBI_REPO="${1#*=}"
                shift
                ;;
            --obi-repo)
                require_option_value "$1" "${2:-}"
                OBI_REPO="${2:-}"
                shift 2
                ;;
            --workdir=*)
                WORKDIR="${1#*=}"
                shift
                ;;
            --workdir)
                require_option_value "$1" "${2:-}"
                WORKDIR="${2:-}"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --skip-ci-check)
                SKIP_CI_CHECK=true
                shift
                ;;
            --exclude-check=*)
                EXCLUDE_CHECK_NAME="${1#*=}"
                shift
                ;;
            --exclude-check)
                require_option_value "$1" "${2:-}"
                EXCLUDE_CHECK_NAME="${2:-}"
                shift 2
                ;;
            --skip-upstream-sync-check)
                SKIP_UPSTREAM_SYNC_CHECK=true
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

    if [[ "$COMMAND" == "tag" && -n "$BUMP_MODE" && "$BUMP_MODE" != "auto" ]]; then
        log_warn "--bump is ignored for the tag command."
    fi
}

main() {
    parse_args "$@"

    case "$COMMAND" in
        prepare)
            prepare_command
            ;;
        tag)
            tag_command
            ;;
        *)
            die "Unhandled command: ${COMMAND}"
            ;;
    esac
}

main "$@"
