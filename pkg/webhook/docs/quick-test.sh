#!/bin/bash
# Quick Test Script for SDK Injection Metrics
# Run this on your remote Linux development machine
#
# What this script does:
#   1. Creates a kind cluster
#   2. Installs cert-manager (for TLS certs the webhook requires)
#   3. Builds beyla:local and loads it into kind
#   4. Deploys Beyla (to the 'default' namespace, same as the example YAMLs)
#   5. Overrides the ConfigMap to enable internal metrics on port 9090
#   6. Deploys a test Java app and checks that injection metrics appear

set -e

echo "======================================"
echo "Beyla SDK Injection Metrics Test"
echo "======================================"
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error()  { echo -e "${RED}[✗]${NC} $1"; }
print_info()   { echo -e "${YELLOW}[i]${NC} $1"; }

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
echo "Checking prerequisites..."

for cmd in docker kubectl kind; do
    if ! command -v "$cmd" &>/dev/null; then
        print_error "$cmd not found. Please install it first."
        exit 1
    fi
    print_status "$cmd installed"
done

# ---------------------------------------------------------------------------
# Step 1: Kind cluster
# ---------------------------------------------------------------------------
echo ""
echo "Step 1: Creating kind cluster..."
if kind get clusters 2>/dev/null | grep -q "^beyla-test$"; then
    print_info "Cluster 'beyla-test' already exists. Deleting and recreating..."
    kind delete cluster --name beyla-test
fi
kind create cluster --name beyla-test
print_status "Kind cluster created"

# ---------------------------------------------------------------------------
# Step 2: cert-manager
# ---------------------------------------------------------------------------
echo ""
echo "Step 2: Installing cert-manager..."
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
echo "Waiting for cert-manager to be ready (up to 2 min)..."
kubectl wait --for=condition=Available deployment/cert-manager-webhook \
    -n cert-manager --timeout=120s
print_status "cert-manager is ready"

# ---------------------------------------------------------------------------
# Step 3: Build beyla:local
# ---------------------------------------------------------------------------
echo ""
echo "Step 3: Building Beyla image..."
print_info "This may take several minutes the first time..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

cd "$REPO_ROOT"
docker build -t beyla:local -f Dockerfile .
print_status "Beyla image built"

echo "Loading image into kind cluster..."
kind load docker-image beyla:local --name beyla-test
print_status "Image loaded"

# ---------------------------------------------------------------------------
# Step 4: Deploy Beyla base manifests (into 'default' namespace)
# ---------------------------------------------------------------------------
echo ""
echo "Step 4: Deploying Beyla base manifests..."

# Use beyla.yaml (hostPath approach, works on all kind versions)
kubectl apply -f "$REPO_ROOT/pkg/webhook/example/beyla.yaml"
print_status "Base Beyla manifests applied (namespace: default)"

# ---------------------------------------------------------------------------
# Step 5: Override the ConfigMap with our test config
#
# Key differences from the base beyla.yaml ConfigMap:
#   - internal_metrics.prometheus.port: 9090  (not 6060 — that's pprof)
#   - injector.instrument uses specific namespaces (not "*")
#   - injector.instrument field is inside 'injector', not 'discovery'
#   - k8s_namespace (not k8s_namespace_name)
# ---------------------------------------------------------------------------
echo ""
echo "Step 5: Applying test ConfigMap with internal metrics enabled..."

cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: beyla-config
  namespace: default
data:
  beyla-config.yml: |
    internal_metrics:
      prometheus:
        port: 9090
        path: /internal/metrics

    injector:
      webhook:
        enable: true
        port: 8443
        cert_path: /etc/webhook/certs/tls.crt
        key_path: /etc/webhook/certs/tls.key
        timeout: 60s

      # 'instrument' lives inside 'injector', not 'discovery'.
      # Field name is k8s_namespace (not k8s_namespace_name).
      instrument:
        - k8s_namespace: "test-success"
        - k8s_namespace: "test-restart"

      sdk_package_version: v0.0.9
      host_mount_path: /var/lib/beyla/instrumentation
      manage_sdk_versions: true

      enabled_sdks:
        - java
        - dotnet
        - nodejs
        - python

    routes:
      ignored_patterns:
        - /health
        - /ready
      unmatched: heuristic
EOF

print_status "Test ConfigMap applied"

# Restart the DaemonSet so it picks up the updated ConfigMap
kubectl rollout restart daemonset/beyla
print_status "DaemonSet rollout restarted to pick up new config"

# ---------------------------------------------------------------------------
# Step 6: Wait for Beyla DaemonSet to be ready (in 'default' namespace)
# ---------------------------------------------------------------------------
echo ""
echo "Step 6: Waiting for Beyla DaemonSet to be ready (up to 3 min)..."
print_info "The pod needs cert-manager to issue the TLS secret (~30s)."
print_info "Note: if this hangs, check 'kubectl get events -n default' for FailedCreate"
print_info "errors from the daemonset-controller — this means the webhook is intercepting"
print_info "its own pod creation (bootstrap deadlock). The namespaceSelector in the YAML"
print_info "prevents this, but only if beyla.yaml was applied cleanly."

# Use 'rollout status' rather than 'wait --for=condition=Ready pod' because:
# - rollout restart creates a new pod and terminates the old one simultaneously
# - 'wait --for=condition=Ready pod -l app=beyla' matches BOTH pods and waits
#   for the terminating pod to become Ready, which never happens
if ! kubectl rollout status daemonset/beyla -n default --timeout=180s; then
    print_error "Beyla DaemonSet rollout did not complete after 3 minutes."
    echo ""
    print_info "Beyla pod status:"
    kubectl get pods -n default -l app=beyla -o wide
    echo ""
    print_info "DaemonSet events:"
    kubectl get events -n default --field-selector involvedObject.name=beyla --sort-by='.lastTimestamp' | tail -10
    echo ""
    print_info "Recent Beyla logs (if pod exists):"
    kubectl logs -n default -l app=beyla --tail=50 2>/dev/null || true
    echo ""
    print_info "cert-manager certificate status:"
    kubectl describe certificate beyla-webhook-cert -n default 2>/dev/null || true
    exit 1
fi
print_status "Beyla DaemonSet is ready"

# ---------------------------------------------------------------------------
# Step 7: Deploy test application
# ---------------------------------------------------------------------------
echo ""
echo "Step 7: Deploying test Java application..."
kubectl create namespace test-success 2>/dev/null || true

cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: java-app-success
  namespace: test-success
spec:
  replicas: 1
  selector:
    matchLabels:
      app: java-app
  template:
    metadata:
      labels:
        app: java-app
    spec:
      containers:
      - name: java-app
        image: openjdk:11-jre-slim
        command: ["sh", "-c", "while true; do echo 'Java app running'; sleep 30; done"]
        ports:
        - containerPort: 8080
EOF

print_status "Test application deployed"

# ---------------------------------------------------------------------------
# Step 8: Check metrics
# ---------------------------------------------------------------------------
echo ""
echo "Step 8: Waiting 10s for webhook to process pod creation..."
sleep 10

echo ""
echo "Step 8: Setting up port-forward to internal metrics (port 9090)..."

# Get the beyla pod name (it's in 'default' namespace)
BEYLA_POD=$(kubectl get pod -n default -l app=beyla -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ -z "$BEYLA_POD" ]; then
    print_error "Could not find Beyla pod in 'default' namespace"
    kubectl get pods -n default
    exit 1
fi
print_info "Beyla pod: $BEYLA_POD"

# Port-forward directly to the pod (no Service needed)
kubectl port-forward -n default "pod/$BEYLA_POD" 9090:9090 >/dev/null 2>&1 &
PORT_FORWARD_PID=$!

cleanup() {
    echo ""
    print_info "Cleaning up port-forward (PID $PORT_FORWARD_PID)..."
    kill "$PORT_FORWARD_PID" 2>/dev/null || true
}
trap cleanup EXIT

sleep 2

echo ""
echo "======================================"
echo "METRICS VALIDATION"
echo "======================================"
echo ""

METRICS=$(curl -sf http://localhost:9090/internal/metrics 2>/dev/null | grep beyla_sdk_injection || true)

if [ -z "$METRICS" ]; then
    print_error "No SDK injection metrics found at http://localhost:9090/internal/metrics"
    echo ""
    print_info "Full metrics output (if any):"
    curl -sf http://localhost:9090/internal/metrics 2>/dev/null | head -30 || print_info "(no response)"
    echo ""
    print_info "Recent Beyla logs:"
    kubectl logs -n default "$BEYLA_POD" --tail=60
else
    print_status "SDK Injection Metrics found:"
    echo ""
    echo "$METRICS"
    echo ""

    for metric in beyla_sdk_injection_attempts_total beyla_sdk_injection_successes_total; do
        if echo "$METRICS" | grep -q "$metric"; then
            print_status "$metric present"
        else
            print_error "$metric missing"
        fi
    done

    if echo "$METRICS" | grep -q "beyla_sdk_injection_failures_total"; then
        print_status "beyla_sdk_injection_failures_total present"
    else
        print_info "beyla_sdk_injection_failures_total not present (OK if no failures occurred)"
    fi

    if echo "$METRICS" | grep -q "beyla_sdk_injection_restarts_total"; then
        print_status "beyla_sdk_injection_restarts_total present"
    else
        print_info "beyla_sdk_injection_restarts_total not present (OK if no restarts occurred)"
    fi
fi

echo ""
echo "======================================"
echo "POD INSPECTION (success case)"
echo "======================================"
echo ""

print_info "Checking if test pod was instrumented..."
POD_NAME=$(kubectl get pod -n test-success -l app=java-app -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -z "$POD_NAME" ]; then
    print_error "Test pod not found in 'test-success' namespace"
else
    print_status "Found pod: $POD_NAME"

    if kubectl get pod -n test-success "$POD_NAME" -o yaml | grep -q "LD_PRELOAD"; then
        print_status "Pod has LD_PRELOAD environment variable (injection succeeded)"
    else
        print_error "Pod missing LD_PRELOAD — injection may have failed"
        print_info "Check webhook logs: kubectl logs -n default $BEYLA_POD | grep -i mutate"
    fi

    if kubectl get pod -n test-success "$POD_NAME" -o yaml | grep -q "com.grafana.beyla/instrumented"; then
        print_status "Pod has instrumentation label"
    else
        print_error "Pod missing instrumentation label"
    fi
fi

# ---------------------------------------------------------------------------
# Step 9: Failure scenarios
# Three failure error_types, each producing beyla_sdk_injection_failures_total
# ---------------------------------------------------------------------------
echo ""
echo "Step 9: Deploying failure scenario pods..."

# 9a: already_instrumented — pod with the instrumented label already set.
# Beyla sees it, records attempt + failure, and leaves the pod untouched.
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: already-instrumented
  namespace: test-success
  labels:
    com.grafana.beyla/instrumented: "v0.9.0"
spec:
  containers:
  - name: app
    image: openjdk:11-jre-slim
    command: ["sh", "-c", "while true; do sleep 30; done"]
EOF

# 9b: ld_preload_conflict — pod with a pre-existing LD_PRELOAD.
# Beyla refuses to overwrite it and records a failure instead.
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ld-preload-conflict
  namespace: test-success
spec:
  containers:
  - name: app
    image: openjdk:11-jre-slim
    command: ["sh", "-c", "while true; do sleep 30; done"]
    env:
    - name: LD_PRELOAD
      value: /some/other/library.so
EOF

# 9c: no_matching_language — pod in a namespace not listed under
# injector.instrument. The webhook is still called (namespace not excluded),
# but Beyla doesn't match it and records the failure.
kubectl create namespace test-nomatch 2>/dev/null || true
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: no-match
  namespace: test-nomatch
spec:
  containers:
  - name: app
    image: nginx:latest
EOF

print_status "Failure scenario pods deployed"

echo ""
print_info "Waiting 5s for webhook to process failure pods..."
sleep 5

echo ""
echo "======================================"
echo "FAILURE METRICS VALIDATION"
echo "======================================"
echo ""

FAIL_METRICS=$(curl -sf http://localhost:9090/internal/metrics 2>/dev/null \
    | grep "beyla_sdk_injection_failures_total" || true)

if [ -z "$FAIL_METRICS" ]; then
    print_error "No failure metrics found — check Beyla logs"
    kubectl logs -n default "$BEYLA_POD" --tail=30
else
    print_status "Failure metrics found:"
    echo ""
    echo "$FAIL_METRICS"
    echo ""

    for error_type in already_instrumented ld_preload_conflict no_matching_language; do
        if echo "$FAIL_METRICS" | grep -q "error_type=\"${error_type}\""; then
            print_status "error_type=${error_type}"
        else
            print_error "error_type=${error_type} not found"
        fi
    done
fi

echo ""
echo "======================================"
echo "NEXT STEPS"
echo "======================================"
echo ""
print_info "To continue testing while the port-forward is alive:"
echo "  curl http://localhost:9090/internal/metrics | grep beyla_sdk_injection"
echo ""
print_info "Or re-establish the port-forward later:"
echo "  kubectl port-forward -n default pod/$BEYLA_POD 9090:9090"
echo ""
print_info "Check Beyla logs:"
echo "  kubectl logs -n default $BEYLA_POD"
echo ""
print_info "View test pod:"
echo "  kubectl describe pod -n test-success -l app=java-app"
echo ""
print_info "For full test scenarios, see: pkg/webhook/docs/MetricsTestPlan.md"
echo ""
print_info "To clean up:"
echo "  kind delete cluster --name beyla-test"
echo ""
print_status "Test setup complete!"
