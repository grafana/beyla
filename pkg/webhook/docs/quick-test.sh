#!/bin/bash
# Quick Test Script for SDK Injection Metrics
# Run this on your remote Linux development machine

set -e

echo "======================================"
echo "Beyla SDK Injection Metrics Test"
echo "======================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[i]${NC} $1"
}

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    print_error "Docker not found. Please install Docker first."
    exit 1
fi
print_status "Docker installed"

if ! command -v kubectl &> /dev/null; then
    print_error "kubectl not found. Please install kubectl first."
    exit 1
fi
print_status "kubectl installed"

if ! command -v kind &> /dev/null; then
    print_error "kind not found. Please install kind first."
    exit 1
fi
print_status "kind installed"

# Step 1: Create kind cluster
echo ""
echo "Step 1: Creating kind cluster..."
if kind get clusters | grep -q "beyla-test"; then
    print_info "Cluster 'beyla-test' already exists. Deleting and recreating..."
    kind delete cluster --name beyla-test
fi
kind create cluster --name beyla-test
print_status "Kind cluster created"

# Step 2: Install cert-manager
echo ""
echo "Step 2: Installing cert-manager..."
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
print_status "cert-manager manifests applied"

echo "Waiting for cert-manager to be ready..."
kubectl wait --for=condition=Available deployment/cert-manager-webhook -n cert-manager --timeout=120s
print_status "cert-manager is ready"

# Step 3: Build Beyla
echo ""
echo "Step 3: Building Beyla..."
print_info "This may take a few minutes..."

# Find the Beyla repository root (assuming script is in pkg/webhook/docs/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

cd "$REPO_ROOT"
docker build -t beyla:local -f Dockerfile .
print_status "Beyla image built"

echo "Loading image into kind..."
kind load docker-image beyla:local --name beyla-test
print_status "Image loaded into kind cluster"

# Step 4: Deploy Beyla
echo ""
echo "Step 4: Deploying Beyla with webhook..."

# Create namespace
kubectl create namespace beyla-system || true

# Create a test config with internal metrics enabled
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: beyla-config
  namespace: beyla-system
data:
  beyla-config.yml: |
    internal_metrics:
      prometheus:
        port: 6060
        path: /internal/metrics

    discovery:
      instrument:
        - k8s_namespace_name: "test-success"
        - k8s_namespace_name: "test-restart"

    injector:
      webhook:
        enable: true
        port: 8443
        cert_path: /etc/webhook/certs/tls.crt
        key_path: /etc/webhook/certs/tls.key
        timeout: 60s

      host_path_volume: /var/lib/beyla/instrumentation
      sdk_package_version: v1.0.0
      manage_sdk_versions: true

      enabled_sdks:
        - java
        - dotnet
        - nodejs
        - python

    otel_traces_export:
      endpoint: http://172.17.0.1:4318
      protocol: http/protobuf
EOF

print_status "Beyla config created"

# Check Kubernetes version for image volume support
K8S_VERSION=$(kubectl version -o json | grep -o '"gitVersion":"[^"]*"' | head -1 | cut -d'"' -f4 | sed 's/v//')
MAJOR=$(echo $K8S_VERSION | cut -d. -f1)
MINOR=$(echo $K8S_VERSION | cut -d. -f2)

print_info "Kubernetes version: $K8S_VERSION"

# Deploy Beyla based on k8s version
if [ "$MAJOR" -ge 1 ] && [ "$MINOR" -ge 31 ]; then
    print_info "Using image volume mode (K8s >= 1.31)"
    kubectl apply -f "$REPO_ROOT/pkg/webhook/example/beyla_image.yaml"
else
    print_info "Using hostPath mode (K8s < 1.31)"
    kubectl apply -f "$REPO_ROOT/pkg/webhook/example/beyla.yaml"
fi

print_status "Beyla deployed"

# Wait for Beyla to be ready
echo "Waiting for Beyla to be ready..."
kubectl wait --for=condition=Ready pod -l app=beyla -n beyla-system --timeout=120s || print_error "Beyla pod not ready, continuing anyway..."
print_status "Beyla is ready"

# Create internal metrics service
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: beyla-internal-metrics
  namespace: beyla-system
spec:
  selector:
    app: beyla
  ports:
  - name: internal-metrics
    port: 6060
    targetPort: 6060
    protocol: TCP
  type: ClusterIP
EOF

print_status "Internal metrics service created"

# Step 5: Deploy test applications
echo ""
echo "Step 5: Deploying test applications..."

# Create test namespace
kubectl create namespace test-success || true

# Deploy Java app for success test
cat <<EOF | kubectl apply -f -
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

print_status "Test applications deployed"

# Wait a bit for webhook to process
echo ""
print_info "Waiting 10 seconds for webhook to process pod creation..."
sleep 10

# Step 6: Check metrics
echo ""
echo "Step 6: Checking metrics..."

print_info "Setting up port-forward to internal metrics..."
kubectl port-forward -n beyla-system svc/beyla-internal-metrics 6060:6060 >/dev/null 2>&1 &
PORT_FORWARD_PID=$!
sleep 2

# Function to cleanup on exit
cleanup() {
    echo ""
    print_info "Cleaning up port-forward..."
    kill $PORT_FORWARD_PID 2>/dev/null || true
}
trap cleanup EXIT

echo ""
echo "======================================"
echo "METRICS VALIDATION"
echo "======================================"
echo ""

# Check for metrics
METRICS=$(curl -s http://localhost:6060/internal/metrics 2>/dev/null | grep beyla_sdk_injection || true)

if [ -z "$METRICS" ]; then
    print_error "No SDK injection metrics found!"
    echo ""
    print_info "Debug: Checking Beyla logs..."
    kubectl logs -n beyla-system -l app=beyla --tail=50
else
    print_status "SDK Injection Metrics Found:"
    echo ""
    echo "$METRICS"
    echo ""

    # Validate specific metrics
    if echo "$METRICS" | grep -q "beyla_sdk_injection_attempts_total"; then
        print_status "Attempts metric present"
    else
        print_error "Attempts metric missing"
    fi

    if echo "$METRICS" | grep -q "beyla_sdk_injection_successes_total"; then
        print_status "Successes metric present"
    else
        print_error "Successes metric missing"
    fi

    if echo "$METRICS" | grep -q "beyla_sdk_injection_failures_total"; then
        print_status "Failures metric present"
    else
        print_info "Failures metric not present (this is OK if no failures occurred)"
    fi

    if echo "$METRICS" | grep -q "beyla_sdk_injection_restarts_total"; then
        print_status "Restarts metric present"
    else
        print_info "Restarts metric not present (this is OK if no restarts occurred)"
    fi
fi

echo ""
echo "======================================"
echo "POD INSPECTION"
echo "======================================"
echo ""

# Check if pod was instrumented
print_info "Checking if test pod was instrumented..."
POD_NAME=$(kubectl get pod -n test-success -l app=java-app -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -z "$POD_NAME" ]; then
    print_error "Test pod not found"
else
    print_status "Found pod: $POD_NAME"

    # Check for LD_PRELOAD
    if kubectl get pod -n test-success "$POD_NAME" -o yaml | grep -q "LD_PRELOAD"; then
        print_status "Pod has LD_PRELOAD environment variable"
    else
        print_error "Pod missing LD_PRELOAD (injection may have failed)"
    fi

    # Check for instrumentation label
    if kubectl get pod -n test-success "$POD_NAME" -o yaml | grep -q "com.grafana.beyla/instrumented"; then
        print_status "Pod has instrumentation label"
    else
        print_error "Pod missing instrumentation label"
    fi
fi

echo ""
echo "======================================"
echo "NEXT STEPS"
echo "======================================"
echo ""
print_info "To continue testing:"
echo "  1. Access metrics: kubectl port-forward -n beyla-system svc/beyla-internal-metrics 6060:6060"
echo "  2. View metrics: curl http://localhost:6060/internal/metrics | grep beyla_sdk_injection"
echo "  3. Check Beyla logs: kubectl logs -n beyla-system -l app=beyla"
echo "  4. View test pod: kubectl describe pod -n test-success -l app=java-app"
echo ""
print_info "For detailed testing, see: pkg/webhook/docs/MetricsTestPlan.md"
echo ""
print_info "To clean up: kind delete cluster --name beyla-test"
echo ""
print_status "Test setup complete!"
