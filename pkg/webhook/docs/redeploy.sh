#!/bin/bash
# Fast rebuild and redeploy for webhook development.
#
# Run quick-test.sh once to set up the cluster. Then use this script
# (or 'make webhook-test-redeploy') to iterate on Go code changes.
#
# Total cycle time: ~60-90s (vs 5-10 min for a full Docker build).

set -e

CLUSTER_NAME="${BEYLA_TEST_CLUSTER:-beyla-test}"
NAMESPACE=default
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${YELLOW}[i]${NC} $1"; }

# Verify the cluster exists before doing anything
if ! kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    fail "Kind cluster '${CLUSTER_NAME}' not found."
    echo "  Run './pkg/webhook/docs/quick-test.sh' to set up the cluster first."
    exit 1
fi

kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null 2>&1

cd "$REPO_ROOT"

echo "=== Webhook Dev Redeploy ==="
echo ""

# Step 1: Compile the Go binary locally.
# This reuses incremental build cache — only changed packages recompile.
# Skips eBPF codegen and the Java agent entirely.
echo "[1/4] Compiling beyla binary..."
make compile
ok "Binary built: bin/beyla"

# Step 2: Build a minimal image from the pre-built binary (~2-3 seconds).
echo ""
echo "[2/4] Building dev image..."
docker build -q -t beyla:local -f pkg/webhook/docs/Dockerfile.dev .
ok "Image ready: beyla:local ($(docker image inspect beyla:local --format='{{.Size}}' | numfmt --to=iec))"

# Step 3: Load the image into the kind cluster's container runtime.
echo ""
echo "[3/4] Loading image into kind cluster '${CLUSTER_NAME}'..."
kind load docker-image beyla:local --name "$CLUSTER_NAME"
ok "Image loaded"

# Step 4: Roll out the DaemonSet with the new image.
echo ""
echo "[4/4] Rolling out DaemonSet..."
kubectl rollout restart daemonset/beyla -n "$NAMESPACE"
kubectl rollout status daemonset/beyla -n "$NAMESPACE" --timeout=90s
ok "DaemonSet ready"

# Bounce test pods so they get re-injected by the new Beyla build.
BOUNCED=()
for ns in test-success test-restart test-failure; do
    if kubectl get namespace "$ns" >/dev/null 2>&1; then
        POD_COUNT=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | wc -l)
        if [ "$POD_COUNT" -gt 0 ]; then
            kubectl delete pods --all -n "$ns" --wait=false 2>/dev/null || true
            BOUNCED+=("$ns")
        fi
    fi
done
if [ "${#BOUNCED[@]}" -gt 0 ]; then
    ok "Bounced pods in: ${BOUNCED[*]} (will be re-injected on restart)"
fi

echo ""
echo "=== Done ==="
echo ""
info "Check metrics:   ./pkg/webhook/docs/check.sh"
info "Or via make:     make webhook-test-check"
