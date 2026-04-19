#!/bin/bash
# Quick metrics and injection status check.
# Port-forwards to the Beyla pod, prints sdk injection metrics, then exits.
#
# Usage: ./pkg/webhook/docs/check.sh [namespace]
#   namespace defaults to 'default'

NAMESPACE="${1:-default}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${YELLOW}[i]${NC} $1"; }

BEYLA_POD=$(kubectl get pod -n "$NAMESPACE" -l app=beyla \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [ -z "$BEYLA_POD" ]; then
    fail "No Beyla pod found in namespace '$NAMESPACE'"
    echo "  kubectl get pods -n $NAMESPACE"
    exit 1
fi

info "Beyla pod: $BEYLA_POD"

# Start port-forward and clean it up on exit
kubectl port-forward -n "$NAMESPACE" "pod/$BEYLA_POD" 9090:9090 >/dev/null 2>&1 &
PF_PID=$!
trap "kill $PF_PID 2>/dev/null; wait $PF_PID 2>/dev/null" EXIT
sleep 1

echo ""
echo "=== SDK Injection Metrics ==="
METRICS=$(curl -sf http://localhost:9090/internal/metrics 2>/dev/null \
    | grep "beyla_sdk_injection" || true)

if [ -z "$METRICS" ]; then
    info "No sdk injection metrics yet (no pods have been processed)"
    echo ""
    info "Full metrics output:"
    curl -sf http://localhost:9090/internal/metrics 2>/dev/null | head -20 \
        || fail "Could not reach http://localhost:9090/internal/metrics"
else
    echo "$METRICS"
fi

echo ""
echo "=== Instrumented Pods ==="
COL_FMT="NAME:.metadata.name,INSTRUMENTED:.metadata.labels.com\.grafana\.beyla/instrumented,STATUS:.status.phase"
for ns in test-success test-restart test-failure test-nomatch; do
    if kubectl get namespace "$ns" >/dev/null 2>&1; then
        echo "  namespace: $ns"
        kubectl get pods -n "$ns" -o custom-columns="$COL_FMT" 2>/dev/null \
            | sed 's/^/    /'
    fi
done
