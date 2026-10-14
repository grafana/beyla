#!/usr/bin/env bash
#
# Determine if an upstream OBI PR has been released in Beyla
#
# Usage:
#   ./scripts/release-lookup.sh --obi=995
#   ./scripts/release-lookup.sh --obi 995
#   ./scripts/release-lookup.sh -o 995
#
# Requirements:
#   - gh CLI installed and authenticated (gh auth login)
#   - Run from within the beyla repository

set -euo pipefail

UPSTREAM_REPO="open-telemetry/opentelemetry-ebpf-instrumentation"
FORK_REPO="grafana/opentelemetry-ebpf-instrumentation"
OBI_SUBMODULE=".obi-src"
PR_NUMBER=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

show_help() {
    cat << 'EOF'
Determine if an upstream OBI PR or Issue has been released in Beyla

Usage:
  release-lookup.sh --obi=<NUMBER>
  release-lookup.sh --obi <NUMBER>
  release-lookup.sh -o <NUMBER>

Options:
  --obi, -o       The upstream OBI PR or Issue number to look up
  --help, -h      Show this help message
  --verbose, -v   Show verbose output

Examples:
  # Check if Issue #995 (or its linked PR) is in a Beyla release
  ./scripts/release-lookup.sh --obi=995

  # Check a specific PR
  ./scripts/release-lookup.sh -o 997

Output:
  If the PR is released:
    OBI PR #997 was released as part of Beyla 2.8.5

  If the PR is not yet released:
    OBI Issue #995 (PR #997) was not yet released as part of Beyla

Notes:
  - This tool queries GitHub via the 'gh' CLI, which must be authenticated
  - Run 'gh auth login' if you haven't already
  - If you provide an Issue number, the script finds the linked merged PR
  - The PR must be merged to be tracked in releases
EOF
}

VERBOSE=false

log_verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${CYAN}[debug]${NC} $*" >&2
    fi
}

log_error() {
    echo -e "${RED}[error]${NC} $*" >&2
}

log_info() {
    echo -e "${YELLOW}[info]${NC} $*" >&2
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --obi=*)
            PR_NUMBER="${1#*=}"
            shift
            ;;
        --obi|-o)
            PR_NUMBER="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
done

# Validate PR number
if [[ -z "$PR_NUMBER" ]]; then
    show_help
    exit 1
fi

if ! [[ "$PR_NUMBER" =~ ^[0-9]+$ ]]; then
    log_error "Invalid PR number: $PR_NUMBER"
    exit 1
fi

# Check gh CLI is available
if ! command -v gh &> /dev/null; then
    log_error "gh CLI is not installed. Install it from https://cli.github.com/"
    exit 1
fi

# Check gh is authenticated
if ! gh auth status &> /dev/null; then
    log_error "gh CLI is not authenticated. Run 'gh auth login' first."
    exit 1
fi

# Find beyla repo root
BEYLA_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
    log_error "Not in a git repository. Run this from within the beyla repo."
    exit 1
}

cd "$BEYLA_ROOT"

# Verify we're in beyla repo
if [[ ! -d "$OBI_SUBMODULE" ]]; then
    log_error "OBI submodule not found at $OBI_SUBMODULE. Are you in the beyla repo?"
    exit 1
fi

log_verbose "Looking up #$PR_NUMBER from $UPSTREAM_REPO"

# First, try to fetch as a PR
PR_JSON=""
PR_FETCH_SUCCESS=1
if PR_JSON=$(gh pr view "$PR_NUMBER" --repo "$UPSTREAM_REPO" --json mergeCommit,state,title 2>&1); then
    PR_FETCH_SUCCESS=0
fi

if [[ $PR_FETCH_SUCCESS -ne 0 ]]; then
    # Not a PR - check if it's an issue with a linked PR
    log_verbose "#$PR_NUMBER is not a PR, checking if it's an issue..."
    
    ISSUE_JSON=$(gh api "repos/$UPSTREAM_REPO/issues/$PR_NUMBER" 2>&1) || {
        log_error "Failed to fetch #$PR_NUMBER from $UPSTREAM_REPO (not a PR or issue)"
        exit 1
    }
    
    ISSUE_STATE=$(echo "$ISSUE_JSON" | jq -r '.state')
    ISSUE_TITLE=$(echo "$ISSUE_JSON" | jq -r '.title')
    log_info "Issue #$PR_NUMBER: $ISSUE_TITLE (state: $ISSUE_STATE)"
    
    # Use GraphQL to find PRs that close this issue
    log_verbose "Searching for PRs that close issue #$PR_NUMBER..."
    
    OWNER=$(echo "$UPSTREAM_REPO" | cut -d'/' -f1)
    REPO_NAME=$(echo "$UPSTREAM_REPO" | cut -d'/' -f2)
    
    LINKED_PRS=$(gh api graphql -f query='
    query($owner: String!, $repo: String!, $number: Int!) {
      repository(owner: $owner, name: $repo) {
        issue(number: $number) {
          timelineItems(itemTypes: [CONNECTED_EVENT, CROSS_REFERENCED_EVENT], first: 50) {
            nodes {
              ... on ConnectedEvent {
                subject {
                  ... on PullRequest {
                    number
                    state
                    title
                    mergeCommit { oid }
                  }
                }
              }
              ... on CrossReferencedEvent {
                source {
                  ... on PullRequest {
                    number
                    state
                    title
                    mergeCommit { oid }
                  }
                }
              }
            }
          }
        }
      }
    }' -f owner="$OWNER" -f repo="$REPO_NAME" -F number="$PR_NUMBER" 2>&1) || {
        log_error "Failed to query linked PRs for issue #$PR_NUMBER"
        exit 1
    }
    
    # Extract merged PRs from the response
    MERGED_PR=$(echo "$LINKED_PRS" | jq -r '
        [.data.repository.issue.timelineItems.nodes[] |
         (.subject // .source) |
         select(. != null and .state == "MERGED")] |
        first // empty
    ')
    
    if [[ -z "$MERGED_PR" || "$MERGED_PR" == "null" ]]; then
        log_info "No merged PRs found linked to issue #$PR_NUMBER"
        echo ""
        echo "OBI Issue #$PR_NUMBER has no merged PR and was not yet released as part of Beyla"
        exit 0
    fi
    
    LINKED_PR_NUMBER=$(echo "$MERGED_PR" | jq -r '.number')
    LINKED_PR_TITLE=$(echo "$MERGED_PR" | jq -r '.title')
    MERGE_COMMIT=$(echo "$MERGED_PR" | jq -r '.mergeCommit.oid // empty')
    
    log_info "Found linked PR #$LINKED_PR_NUMBER: $LINKED_PR_TITLE"
    log_verbose "Merge commit: $MERGE_COMMIT"
    
    # Update PR_NUMBER for display purposes
    ORIGINAL_ISSUE="$PR_NUMBER"
    PR_NUMBER="$LINKED_PR_NUMBER"
    PR_STATE="MERGED"
    PR_TITLE="$LINKED_PR_TITLE"
else
    PR_STATE=$(echo "$PR_JSON" | jq -r '.state')
    PR_TITLE=$(echo "$PR_JSON" | jq -r '.title')
    MERGE_COMMIT=$(echo "$PR_JSON" | jq -r '.mergeCommit.oid // empty')
    ORIGINAL_ISSUE=""
fi

log_verbose "PR title: $PR_TITLE"
log_verbose "PR state: $PR_STATE"
log_verbose "Merge commit: ${MERGE_COMMIT:-none}"

if [[ "$PR_STATE" != "MERGED" ]]; then
    log_info "PR #$PR_NUMBER is not merged (state: $PR_STATE)"
    echo ""
    echo "OBI PR #$PR_NUMBER was not yet released as part of Beyla"
    exit 0
fi

if [[ -z "$MERGE_COMMIT" ]]; then
    log_error "PR #$PR_NUMBER is merged but no merge commit found"
    exit 1
fi

log_verbose "Checking if commit $MERGE_COMMIT exists in fork $FORK_REPO"

# First, ensure the submodule has the latest commits fetched
log_verbose "Fetching latest commits in OBI submodule..."
(cd "$OBI_SUBMODULE" && git fetch origin --quiet 2>/dev/null) || {
    log_info "Could not fetch OBI submodule. Continuing with local data."
}

# Check if the commit exists in the local submodule
if ! (cd "$OBI_SUBMODULE" && git cat-file -e "$MERGE_COMMIT" 2>/dev/null); then
    # Try checking via API as fallback
    FORK_COMMIT_CHECK=$(gh api "repos/$FORK_REPO/commits/$MERGE_COMMIT" --jq '.sha' 2>&1) || {
        log_info "Commit $MERGE_COMMIT not found in $FORK_REPO"
        log_info "The upstream commit may not have been synced to the Grafana fork yet."
        echo ""
        if [[ -n "${ORIGINAL_ISSUE:-}" ]]; then
            echo "OBI Issue #$ORIGINAL_ISSUE (PR #$PR_NUMBER) was not yet released as part of Beyla"
        else
            echo "OBI PR #$PR_NUMBER was not yet released as part of Beyla"
        fi
        exit 0
    }
    log_verbose "Commit exists in fork (via API): $FORK_COMMIT_CHECK"
    log_verbose "Attempting to fetch merge commit into local submodule..."
    
    # Try to fetch the specific commit
    if (cd "$OBI_SUBMODULE" && git fetch origin "$MERGE_COMMIT" --quiet 2>/dev/null); then
        log_verbose "Successfully fetched merge commit"
    else
        # Fallback: fetch all from origin and hope it includes the commit
        log_verbose "Could not fetch specific commit, trying full fetch..."
        (cd "$OBI_SUBMODULE" && git fetch origin --quiet 2>/dev/null) || true
        
        # Verify the commit is now available
        if ! (cd "$OBI_SUBMODULE" && git cat-file -e "$MERGE_COMMIT" 2>/dev/null); then
            log_error "Commit $MERGE_COMMIT exists in fork but could not be fetched locally."
            log_error "Try running: cd $OBI_SUBMODULE && git fetch origin"
            exit 1
        fi
        log_verbose "Merge commit now available locally after full fetch"
    fi
else
    log_verbose "Commit exists in local submodule"
fi

# Get all beyla release tags (excluding pre-releases and alloy variants), sorted by version
log_verbose "Fetching Beyla release tags..."
RELEASE_TAGS=$(git tag --list 'v*' | grep -vE '\-(pre|alpha|alloy)' | sort -V)

if [[ -z "$RELEASE_TAGS" ]]; then
    log_error "No release tags found in beyla repo"
    exit 1
fi

log_verbose "Found $(echo "$RELEASE_TAGS" | wc -l | tr -d ' ') release tags"

# For each release tag, check if the merge commit is an ancestor of the OBI submodule commit
FIRST_RELEASE=""

for TAG in $RELEASE_TAGS; do
    # Get the OBI submodule commit for this tag
    OBI_COMMIT=$(git ls-tree "$TAG" "$OBI_SUBMODULE" 2>/dev/null | awk '{print $3}')
    
    if [[ -z "$OBI_COMMIT" ]]; then
        log_verbose "Tag $TAG: no OBI submodule found"
        continue
    fi
    
    log_verbose "Tag $TAG: OBI submodule at $OBI_COMMIT"
    
    # Check if OBI_COMMIT exists locally (it might be an old commit not in current fetch)
    if ! (cd "$OBI_SUBMODULE" && git cat-file -e "$OBI_COMMIT" 2>/dev/null); then
        log_verbose "Tag $TAG: submodule commit not available locally, fetching..."
        (cd "$OBI_SUBMODULE" && git fetch origin "$OBI_COMMIT" --quiet 2>/dev/null) || {
            log_verbose "Tag $TAG: could not fetch submodule commit"
            continue
        }
    fi
    
    # Check if MERGE_COMMIT is an ancestor of OBI_COMMIT using local git
    if (cd "$OBI_SUBMODULE" && git merge-base --is-ancestor "$MERGE_COMMIT" "$OBI_COMMIT" 2>/dev/null); then
        FIRST_RELEASE="$TAG"
        log_verbose "Found! First release containing the commit: $TAG"
        break
    else
        log_verbose "Tag $TAG: merge commit is NOT an ancestor of submodule commit"
    fi
done

echo ""
if [[ -n "$FIRST_RELEASE" ]]; then
    # Strip 'v' prefix for display
    VERSION="${FIRST_RELEASE#v}"
    if [[ -n "${ORIGINAL_ISSUE:-}" ]]; then
        echo -e "${GREEN}OBI Issue #$ORIGINAL_ISSUE (PR #$PR_NUMBER) was released as part of Beyla $VERSION${NC}"
    else
        echo -e "${GREEN}OBI PR #$PR_NUMBER was released as part of Beyla $VERSION${NC}"
    fi
else
    if [[ -n "${ORIGINAL_ISSUE:-}" ]]; then
        echo "OBI Issue #$ORIGINAL_ISSUE (PR #$PR_NUMBER) was not yet released as part of Beyla"
    else
        echo "OBI PR #$PR_NUMBER was not yet released as part of Beyla"
    fi
fi

