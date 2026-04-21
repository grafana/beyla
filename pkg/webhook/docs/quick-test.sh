#!/bin/bash
# Beyla SDK Injection — Story-mode test script
#
# Story arc (watch in Grafana as the script runs):
#
#   Phase A — pre-existing workloads land first, before Beyla.
#              Dashboard shows pending_restart spike as Beyla comes up,
#              then drops to zero as Beyla bounces each pod.
#
#   Phase B — fresh workloads deployed after Beyla.
#              Dashboard shows instrumented count climb immediately.
#
#   Phase C — problem workloads:  skipped/conflict, skipped/already_instrumented,
#              and unmatched (in-scope namespace, label selector not met).
#              All four status values now visible simultaneously.
#
#   Phase D — continuous pod churn (background pulse).
#              Event-counter time series show a steady sawtooth pattern.
#
# Namespaces used:
#   test-preexisting   — 3-replica Deployment created BEFORE Beyla → pending → instrumented
#   test-instrumented  — 3-replica Deployment created AFTER Beyla  → immediately instrumented
#   test-conflict      — 2-replica Deployment with LD_PRELOAD set   → skipped/conflict
#   test-skipped       — 1-replica Deployment already labelled      → skipped/already_instrumented
#   test-unmatched     — 2-replica Deployment without required label → unmatched
#                        (selector requires k8s_pod_labels: inject=true)
#
# --- Optional: Grafana Cloud remote-write (step 6b) ---
# Deploys a Prometheus pod that scrapes Beyla's /internal/metrics and remote-writes
# to your Grafana Cloud Prometheus endpoint.
#
#   export GRAFANA_PROM_REMOTE_WRITE_URL="https://prometheus-prod-XX-XXX.grafana.net/api/prom/push"
#   export GRAFANA_PROM_USERNAME="123456"
#   export GRAFANA_PROM_PASSWORD="glsa_xxxx..."
#
# Where to get these: Grafana Cloud → (your stack) → Details → Prometheus section
#
# --- Optional: Grafana Cloud eBPF Beyla (step 2b) ---
# Separate from the webhook. Instruments app traffic via eBPF and exports via OTLP.
#   export GRAFANA_OTLP_HEADERS="Authorization=Basic <base64>"
#   export GRAFANA_OTLP_ENDPOINT="..."   # optional override

set -e

echo "============================================================"
echo " Beyla SDK Injection — Coverage Story Test"
echo "============================================================"
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error()  { echo -e "${RED}[✗]${NC} $1"; }
print_info()   { echo -e "${YELLOW}[i]${NC} $1"; }

phase() {
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}  PHASE: $1${NC}"
    echo -e "${CYAN}  $2${NC}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# Print current beyla_injection_pods samples grouped by status.
# Requires the port-forward to already be alive.
show_state_metric() {
    local raw
    raw=$(curl -sf http://localhost:9090/internal/metrics 2>/dev/null \
        | grep 'beyla_injection_pods{' || true)

    if [ -z "$raw" ]; then
        print_info "beyla_injection_pods — no samples yet"
        return
    fi

    echo "  beyla_injection_pods (current scrape):"
    echo "$raw" | sort | while IFS= read -r line; do
        echo "    $line"
    done

    local instrumented pending skipped unmatched
    instrumented=$(echo "$raw" | grep 'status="instrumented"' \
        | awk '{sum += $NF} END {print sum+0}')
    pending=$(echo "$raw" | grep 'status="pending_restart"' \
        | awk '{sum += $NF} END {print sum+0}')
    skipped=$(echo "$raw" | grep 'status="skipped"' \
        | awk '{sum += $NF} END {print sum+0}')
    unmatched=$(echo "$raw" | grep 'status="unmatched"' \
        | awk '{sum += $NF} END {print sum+0}')

    echo ""
    echo "  Summary: instrumented=${instrumented}  pending_restart=${pending}  skipped=${skipped}  unmatched=${unmatched}"
}

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

if [ -n "${GRAFANA_OTLP_HEADERS:-}" ]; then
    if ! command -v helm &>/dev/null; then
        print_error "helm not found — required when GRAFANA_OTLP_HEADERS is set"
        exit 1
    fi
    print_status "helm installed (Grafana Cloud eBPF step enabled)"
fi

GRAFANA_OTLP_ENDPOINT="${GRAFANA_OTLP_ENDPOINT:-http://grafana-k8s-monitoring-alloy.default.svc.cluster.local:4318}"

# ---------------------------------------------------------------------------
# Step 1: Kind cluster
# ---------------------------------------------------------------------------
echo ""
echo "Step 1: Creating kind cluster..."
if kind get clusters 2>/dev/null | grep -q "^beyla-test$"; then
    print_info "Cluster 'beyla-test' already exists — deleting and recreating..."
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
# Step 2b: Grafana Cloud eBPF Beyla (optional)
# ---------------------------------------------------------------------------
if [ -n "${GRAFANA_OTLP_HEADERS:-}" ]; then
    echo ""
    echo "Step 2b: Deploying Grafana Cloud eBPF Beyla..."
    kubectl get ns beyla >/dev/null 2>&1 || kubectl create ns beyla
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: grafana-secret
  namespace: beyla
type: Opaque
stringData:
  otlp-headers: "${GRAFANA_OTLP_HEADERS}"
EOF
    helm repo add grafana https://grafana.github.io/helm-charts 2>/dev/null || true
    helm repo update grafana
    helm upgrade --install --atomic --timeout 300s beyla grafana/beyla \
        --namespace beyla --create-namespace \
        --values - <<EOF
config:
  data:
    discovery:
      instrument:
        - k8s_namespace: test-instrumented
        - k8s_namespace: test-preexisting
    routes:
      unmatched: heuristic
    env:
      OTEL_EXPORTER_OTLP_ENDPOINT: "${GRAFANA_OTLP_ENDPOINT}"
    envValueFrom:
      OTEL_EXPORTER_OTLP_HEADERS:
        secretKeyRef:
          name: grafana-secret
          key: otlp-headers
EOF
    print_status "Grafana Cloud eBPF Beyla deployed in 'beyla' namespace"
else
    print_info "Skipping Grafana Cloud eBPF step (set GRAFANA_OTLP_HEADERS to enable)"
fi

# ---------------------------------------------------------------------------
# Step 2c: Pre-existing workloads — deployed BEFORE Beyla.
#
# These pods land in a watched namespace while the webhook doesn't exist yet.
# When Beyla starts, it sees them as pending_restart, then bounces them.
# This creates the most important transition in the dashboard story:
#   pending_restart spikes → drops to zero → instrumented climbs.
# ---------------------------------------------------------------------------
echo ""
echo "Step 2c: Deploying pre-existing workloads (before Beyla)..."

for ns in test-preexisting test-instrumented test-conflict test-skipped test-unmatched; do
    kubectl create namespace "$ns" 2>/dev/null || true
done
print_status "Test namespaces created"

kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: legacy-app
  namespace: test-preexisting
  labels:
    scenario: pre-existing
spec:
  replicas: 3
  selector:
    matchLabels:
      app: legacy-app
  template:
    metadata:
      labels:
        app: legacy-app
    spec:
      containers:
        - name: app
          image: busybox
          command: ["sh", "-c", "while true; do sleep 30; done"]
          resources:
            limits:
              memory: 32Mi
EOF
print_status "pre-existing: legacy-app (3 replicas) deployed — will appear as pending_restart"

# ---------------------------------------------------------------------------
# Step 3: Build Beyla image
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
# Step 4: Deploy Beyla webhook base manifests
# ---------------------------------------------------------------------------
echo ""
echo "Step 4: Deploying Beyla webhook manifests..."
kubectl apply -f "$REPO_ROOT/pkg/webhook/example/beyla.yaml"
print_status "Base Beyla manifests applied (namespace: default)"

# Exclude 'beyla' namespace so the eBPF Beyla pod isn't intercepted by the webhook.
kubectl patch mutatingwebhookconfiguration beyla-mutating-webhook \
    --type='json' \
    -p='[{"op":"add","path":"/webhooks/0/namespaceSelector/matchExpressions/0/values/-","value":"beyla"}]' \
    2>/dev/null && print_status "Excluded 'beyla' namespace from webhook" \
    || print_info "Webhook namespace patch skipped (not needed or not ready yet)"

# ---------------------------------------------------------------------------
# Step 5: ConfigMap — five namespaces, pod-label constraint for unmatched
#
# test-unmatched uses a pod-label selector: only pods with inject=true match.
# Pods without that label are in-scope but unmatched — they appear in the
# dashboard as status=unmatched rather than being ignored entirely.
# ---------------------------------------------------------------------------
echo ""
echo "Step 5: Applying test ConfigMap..."

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
        key_path:  /etc/webhook/certs/tls.key
        timeout: 60s

      instrument:
        - k8s_namespace: "test-preexisting"
        - k8s_namespace: "test-instrumented"
        - k8s_namespace: "test-conflict"
        - k8s_namespace: "test-skipped"
        # test-unmatched: in scope, but only pods with label inject=true get instrumented.
        # Pods WITHOUT the label show as status=unmatched.
        - k8s_namespace: "test-unmatched"
          k8s_pod_labels:
            inject: "true"

      sdk_package_version: v0.0.9
      host_mount_path: /var/lib/beyla/instrumentation
      manage_sdk_versions: true

      enabled_sdks:
        - java
        - dotnet
        - nodejs
        - python

    routes:
      unmatched: heuristic
EOF

print_status "ConfigMap applied (5 namespaces, pod-label selector for unmatched)"

kubectl rollout restart daemonset/beyla
print_status "DaemonSet rollout restarted to pick up new config"

# ---------------------------------------------------------------------------
# Step 6: Wait for Beyla
# ---------------------------------------------------------------------------
echo ""
echo "Step 6: Waiting for Beyla DaemonSet to be ready (up to 3 min)..."
print_info "cert-manager is issuing the TLS secret for the webhook (~30s)."

if ! kubectl rollout status daemonset/beyla -n default --timeout=180s; then
    print_error "Beyla DaemonSet rollout did not complete after 3 minutes."
    kubectl get pods -n default -l app=beyla -o wide
    kubectl get events -n default --field-selector involvedObject.name=beyla --sort-by='.lastTimestamp' | tail -10
    kubectl logs -n default -l app=beyla --tail=50 2>/dev/null || true
    exit 1
fi
print_status "Beyla DaemonSet is ready"

# ---------------------------------------------------------------------------
# Port-forward to Beyla's internal metrics — opened now so all phase
# checkpoints and validation steps can use it.
# ---------------------------------------------------------------------------
BEYLA_POD=$(kubectl get pod -n default -l app=beyla \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ -z "$BEYLA_POD" ]; then
    print_error "Could not find Beyla pod in 'default' namespace"
    kubectl get pods -n default
    exit 1
fi
print_info "Beyla pod: $BEYLA_POD"

kubectl port-forward -n default "pod/$BEYLA_POD" 9090:9090 >/dev/null 2>&1 &
PORT_FORWARD_PID=$!

# Cleanup: kill port-forward and pulse loop on exit
PULSE_PID=""
cleanup() {
    echo ""
    print_info "Cleaning up background processes..."
    [ -n "$PORT_FORWARD_PID" ] && kill "$PORT_FORWARD_PID" 2>/dev/null || true
    [ -n "$PULSE_PID" ]        && kill "$PULSE_PID"        2>/dev/null || true
}
trap cleanup EXIT

sleep 3   # give the port-forward time to establish

# ---------------------------------------------------------------------------
# Phase A: Beyla just started — pre-existing pods show as pending_restart.
#
# WHY Beyla does NOT auto-bounce these pods:
#   Beyla's bouncer only restarts pre-existing pods when it can confirm a
#   supported language (Java/dotnet/Node.js/Python) is running inside them via
#   /proc scanning. The busybox containers here run 'sleep', which has no
#   language fingerprint — Beyla sees them as InstrumentableGeneric, which is
#   not in enabled_sdks, and deliberately skips them.
#
#   In production with a real Java or Node.js app, the scanner would find
#   libjvm.so or the node binary in the process maps and trigger the bounce
#   automatically. For this test script we trigger it manually to show the
#   dashboard transition, exactly as an operator would do in practice.
# ---------------------------------------------------------------------------
phase "A — Beyla online, legacy-app stuck at pending_restart" \
      "Beyla sees 3 pre-existing pods but cannot detect their language. pending_restart=3."

show_state_metric

print_info "Confirming pending_restart state before triggering manual rollout..."
sleep 5

# Manually restart the pre-existing Deployment. In production this would happen
# naturally (rolling deploy, node drain, etc.) or an operator would run this
# after installing Beyla to instrument existing workloads immediately.
print_info "Triggering rollout restart of legacy-app → new pods admitted through webhook..."
kubectl rollout restart deployment/legacy-app -n test-preexisting

echo "Waiting for rollout to complete (new pods go through webhook admission → instrumented)..."
kubectl rollout status deployment/legacy-app -n test-preexisting --timeout=120s

print_info "Rollout done. Waiting 10s for state metric to update..."
sleep 10

phase "A (after rollout) — legacy-app transitioning to instrumented" \
      "pending_restart should now be 0; instrumented should show 3."

show_state_metric

# ---------------------------------------------------------------------------
# Step 6b: Prometheus → Grafana Cloud remote-write (optional)
# ---------------------------------------------------------------------------
if [ -n "${GRAFANA_PROM_REMOTE_WRITE_URL:-}" ] && \
   [ -n "${GRAFANA_PROM_USERNAME:-}" ] && \
   [ -n "${GRAFANA_PROM_PASSWORD:-}" ]; then

    echo ""
    echo "Step 6b: Deploying Prometheus with Grafana Cloud remote-write..."

    # Expose Beyla's metrics port as a ClusterIP Service so Prometheus can scrape
    # it reliably even though the DaemonSet pod uses hostNetwork.
    kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Service
metadata:
  name: beyla-metrics
  namespace: default
spec:
  selector:
    app: beyla
  ports:
    - name: internal-metrics
      port: 9090
      targetPort: 9090
EOF

    PROM_REMOTE_WRITE_URL="${GRAFANA_PROM_REMOTE_WRITE_URL}"
    PROM_USERNAME="${GRAFANA_PROM_USERNAME}"
    PROM_PASSWORD="${GRAFANA_PROM_PASSWORD}"

    kubectl create configmap prometheus-remote-write-config \
        --namespace default \
        --dry-run=client -o yaml \
        --from-literal=prometheus.yml="
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: beyla-test

scrape_configs:
  - job_name: beyla-injection
    metrics_path: /internal/metrics
    static_configs:
      - targets: ['beyla-metrics.default.svc.cluster.local:9090']

remote_write:
  - url: ${PROM_REMOTE_WRITE_URL}
    basic_auth:
      username: '${PROM_USERNAME}'
      password: '${PROM_PASSWORD}'
    write_relabel_configs:
      - source_labels: [__name__]
        regex: 'beyla_(injection_pods|sdk_injection_.+)'
        action: keep
" | kubectl apply -f -

    kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: prometheus-remote-write
  namespace: default
spec:
  containers:
    - name: prometheus
      image: quay.io/prometheus/prometheus:v2.55.1
      args:
        - --config.file=/etc/prometheus/prometheus.yml
        - --storage.tsdb.retention.time=2h
        - --web.enable-lifecycle
      volumeMounts:
        - name: config
          mountPath: /etc/prometheus
      resources:
        limits:
          memory: 256Mi
  volumes:
    - name: config
      configMap:
        name: prometheus-remote-write-config
EOF

    kubectl wait pod/prometheus-remote-write \
        --for=condition=Ready --namespace default --timeout=60s
    print_status "Prometheus deployed — remote-writing to Grafana Cloud"
    print_info "Metrics appear in Grafana Cloud within ~30s"
else
    print_info "Grafana Cloud remote-write disabled (set GRAFANA_PROM_REMOTE_WRITE_URL + credentials)"
fi

# ---------------------------------------------------------------------------
# Step 7: Deploy all scenario workloads
# ---------------------------------------------------------------------------
echo ""
echo "Step 7: Deploying scenario workloads..."

# 7a: Fresh instrumented workload — 3 replicas, deployed AFTER Beyla.
#     Pods are mutated at admission time → immediately instrumented.
kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fresh-app
  namespace: test-instrumented
  labels:
    scenario: instrumented
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fresh-app
  template:
    metadata:
      labels:
        app: fresh-app
    spec:
      containers:
        - name: app
          image: busybox
          command: ["sh", "-c", "while true; do sleep 30; done"]
          resources:
            limits:
              memory: 32Mi
EOF
print_status "test-instrumented: fresh-app (3 replicas) → status=instrumented"

# 7b: Conflict — containers already have LD_PRELOAD set to another library.
#     Webhook refuses to overwrite → status=skipped, skip_reason=conflict.
kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: conflict-app
  namespace: test-conflict
  labels:
    scenario: conflict
spec:
  replicas: 2
  selector:
    matchLabels:
      app: conflict-app
  template:
    metadata:
      labels:
        app: conflict-app
    spec:
      containers:
        - name: app
          image: busybox
          command: ["sh", "-c", "while true; do sleep 30; done"]
          env:
            - name: LD_PRELOAD
              value: /vendor/security/libfortify.so
          resources:
            limits:
              memory: 32Mi
EOF
print_status "test-conflict: conflict-app (2 replicas) → status=skipped, skip_reason=conflict"

# 7c: Already instrumented — pod carries our instrumentation label as if a previous
#     Beyla version had already processed it. Webhook skips re-instrumentation.
#     status=skipped, skip_reason=already_instrumented.
kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: already-instrumented-app
  namespace: test-skipped
  labels:
    scenario: already-instrumented
spec:
  replicas: 1
  selector:
    matchLabels:
      app: already-instrumented-app
  template:
    metadata:
      labels:
        app: already-instrumented-app
        # This label signals "we already processed this pod" — webhook skips it.
        com.grafana.beyla/instrumented: "v0.0.8"
    spec:
      containers:
        - name: app
          image: busybox
          command: ["sh", "-c", "while true; do sleep 30; done"]
          resources:
            limits:
              memory: 32Mi
EOF
print_status "test-skipped: already-instrumented-app (1 replica) → status=skipped, skip_reason=already_instrumented"

# 7d: Unmatched — namespace IS in scope, but pods lack the required inject=true label.
#     The selector in the ConfigMap has k8s_pod_labels: inject: "true".
#     These pods are visible to the collector but match no selector → status=unmatched.
kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: unlabeled-app
  namespace: test-unmatched
  labels:
    scenario: unmatched
spec:
  replicas: 2
  selector:
    matchLabels:
      app: unlabeled-app
  template:
    metadata:
      labels:
        app: unlabeled-app
        # Deliberately missing: inject: "true"
    spec:
      containers:
        - name: app
          image: busybox
          command: ["sh", "-c", "while true; do sleep 30; done"]
          resources:
            limits:
              memory: 32Mi
EOF
print_status "test-unmatched: unlabeled-app (2 replicas, no inject label) → status=unmatched"

# 7e: Labeled in unmatched namespace — has inject=true, so it IS matched and instrumented.
#     The dashboard now shows test-unmatched with BOTH unmatched (2) and instrumented (1).
kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: labeled-app
  namespace: test-unmatched
  labels:
    scenario: labeled-in-unmatched
spec:
  replicas: 1
  selector:
    matchLabels:
      app: labeled-app
  template:
    metadata:
      labels:
        app: labeled-app
        inject: "true"    # matches the pod-label selector → instrumented
    spec:
      containers:
        - name: app
          image: busybox
          command: ["sh", "-c", "while true; do sleep 30; done"]
          resources:
            limits:
              memory: 32Mi
EOF
print_status "test-unmatched: labeled-app (1 replica, inject=true) → status=instrumented"

print_info "Waiting 15s for webhook to process all new pods..."
sleep 15

# ---------------------------------------------------------------------------
# Step 7b: Background pulse — continuous pod churn for time-series motion.
#
# Every 90s: creates a short-lived pod in test-instrumented, waits for it to
# be admitted and mutated (drives beyla_sdk_injection_attempts_total), then
# deletes it. The cycle repeats indefinitely while this script is running.
# ---------------------------------------------------------------------------
run_pulse() {
    local counter=0
    while true; do
        counter=$((counter + 1))
        kubectl run "pulse-${counter}" \
            --namespace test-instrumented \
            --image=busybox \
            --restart=Never \
            --labels="app=pulse,scenario=churn" \
            --command -- sh -c "sleep 20" \
            2>/dev/null || true
        sleep 45
        kubectl delete pod "pulse-${counter}" \
            --namespace test-instrumented \
            --ignore-not-found \
            2>/dev/null || true
        sleep 45
    done
}

run_pulse &
PULSE_PID=$!
print_status "Background pulse started (PID ${PULSE_PID}) — creating/deleting pods every 90s"
print_info "This drives beyla_sdk_injection_attempts_total for the event-counter panels"

# ---------------------------------------------------------------------------
# Phase B: All four statuses in play.
# ---------------------------------------------------------------------------
phase "B — All statuses visible" \
      "instrumented (pre-existing + fresh + labeled), pending_restart (if any), skipped (conflict + already_instrumented), unmatched."

show_state_metric

# ---------------------------------------------------------------------------
# Validation: event counters
# ---------------------------------------------------------------------------
echo ""
echo "======================================"
echo "EVENT COUNTER VALIDATION"
echo "======================================"
echo ""

METRICS=$(curl -sf http://localhost:9090/internal/metrics 2>/dev/null \
    | grep "beyla_sdk_injection" || true)

if [ -z "$METRICS" ]; then
    print_error "No SDK injection metrics found — check Beyla logs"
    kubectl logs -n default "$BEYLA_POD" --tail=30
else
    print_status "SDK injection event counters:"
    echo ""
    echo "$METRICS"
    echo ""

    for metric in beyla_sdk_injection_attempts_total \
                  beyla_sdk_injection_successes_total \
                  beyla_sdk_injection_failures_total; do
        if echo "$METRICS" | grep -q "$metric"; then
            print_status "$metric present"
        else
            print_info "$metric not yet present (OK if no events of that type yet)"
        fi
    done
fi

# ---------------------------------------------------------------------------
# Validation: state metric final snapshot
# ---------------------------------------------------------------------------
echo ""
echo "======================================"
echo "STATE METRIC FINAL SNAPSHOT"
echo "======================================"
echo ""

show_state_metric

STATE_METRICS=$(curl -sf http://localhost:9090/internal/metrics 2>/dev/null \
    | grep "beyla_injection_pods{" || true)

if [ -z "$STATE_METRICS" ]; then
    print_error "beyla_injection_pods not found — check that ConfigMap sets internal_metrics.prometheus.port: 9090"
else
    for check_status in instrumented skipped unmatched; do
        if echo "$STATE_METRICS" | grep -q "status=\"${check_status}\""; then
            print_status "status=${check_status} samples present"
        else
            print_error "status=${check_status} missing — check workload deployment above"
        fi
    done

    if echo "$STATE_METRICS" | grep -q 'skip_reason="conflict"'; then
        print_status "skip_reason=conflict present"
    else
        print_error "skip_reason=conflict missing"
    fi

    if echo "$STATE_METRICS" | grep -q 'skip_reason="already_instrumented"'; then
        print_status "skip_reason=already_instrumented present"
    else
        print_error "skip_reason=already_instrumented missing"
    fi

    for sys_ns in kube-system kube-node-lease kube-public; do
        if echo "$STATE_METRICS" | grep -q "k8s_namespace_name=\"${sys_ns}\""; then
            print_error "System namespace ${sys_ns} should be excluded from the metric"
        else
            print_status "${sys_ns} correctly excluded"
        fi
    done
fi

# ---------------------------------------------------------------------------
# Pod instrumentation spot-check
# ---------------------------------------------------------------------------
echo ""
echo "======================================"
echo "POD SPOT-CHECKS"
echo "======================================"
echo ""

check_pod_instrumented() {
    local ns="$1" label="$2" expect_ld_preload="$3"
    local pod
    pod=$(kubectl get pod -n "$ns" -l "$label" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [ -z "$pod" ]; then
        print_error "$ns / $label — pod not found"
        return
    fi
    if [ "$expect_ld_preload" = "yes" ]; then
        if kubectl get pod -n "$ns" "$pod" -o yaml 2>/dev/null | grep -q "LD_PRELOAD.*libotelinject"; then
            print_status "$ns / $pod — has our LD_PRELOAD (instrumented)"
        else
            print_error "$ns / $pod — missing our LD_PRELOAD"
        fi
    else
        if kubectl get pod -n "$ns" "$pod" -o yaml 2>/dev/null | grep -q "LD_PRELOAD.*libotelinject"; then
            print_error "$ns / $pod — should NOT have our LD_PRELOAD, but does"
        else
            print_status "$ns / $pod — correctly not instrumented by us"
        fi
    fi
}

check_pod_instrumented "test-instrumented"   "app=fresh-app"               "yes"
check_pod_instrumented "test-preexisting"     "app=legacy-app"              "yes"
check_pod_instrumented "test-conflict"        "app=conflict-app"            "no"
check_pod_instrumented "test-skipped"         "app=already-instrumented-app" "no"
check_pod_instrumented "test-unmatched"       "app=labeled-app"             "yes"
check_pod_instrumented "test-unmatched"       "app=unlabeled-app"           "no"

# ---------------------------------------------------------------------------
# NEXT STEPS
# ---------------------------------------------------------------------------
echo ""
echo "======================================"
echo "NEXT STEPS"
echo "======================================"
echo ""

print_info "The background pulse (PID ${PULSE_PID}) keeps running — event counters will increment."
print_info "Leave the script running and watch the Grafana dashboard update."
echo ""
print_info "Re-establish port-forward if needed:"
echo "  kubectl port-forward -n default pod/$BEYLA_POD 9090:9090"
echo ""
print_info "Live metric feed:"
echo "  watch -n5 'curl -s http://localhost:9090/internal/metrics | grep beyla_injection_pods'"
echo ""
print_info "Namespace summary:"
echo "  test-preexisting  → instrumented (3 pods — was pending_restart at Phase A)"
echo "  test-instrumented → instrumented (3 pods + pulse)"
echo "  test-conflict     → skipped/conflict (2 pods)"
echo "  test-skipped      → skipped/already_instrumented (1 pod)"
echo "  test-unmatched    → unmatched (2 pods) + instrumented (1 pod with inject=true)"
echo ""

if [ -n "${GRAFANA_PROM_REMOTE_WRITE_URL:-}" ]; then
    print_info "Grafana Cloud — open Explore and run:"
    echo "  beyla_injection_pods{cluster=\"beyla-test\"}"
    echo ""
    print_info "Check remote-write logs:"
    echo "  kubectl logs -n default prometheus-remote-write | tail -20"
    echo ""
fi

if [ -n "${GRAFANA_OTLP_HEADERS:-}" ]; then
    print_info "eBPF Beyla logs:"
    echo "  kubectl logs -n beyla -l app.kubernetes.io/name=beyla"
    echo ""
fi

print_info "Why busybox stays pending_restart without manual restart:"
echo "  Beyla's bouncer only auto-restarts pods where it detects Java/dotnet/Node/Python"
echo "  via /proc scanning. 'sleep' has no language fingerprint → InstrumentableGeneric."
echo "  Real Java/Node apps bounce automatically. Busybox needs: kubectl rollout restart."
echo ""
print_info "Simulate a config change (remove test-preexisting from scope, restart Beyla):"
echo "  kubectl edit configmap beyla-config -n default   # remove test-preexisting entry"
echo "  kubectl rollout restart daemonset/beyla -n default"
echo "  # Watch test-preexisting disappear from the metric"
echo ""
print_info "Clean up:"
echo "  kind delete cluster --name beyla-test"
echo ""
print_status "Setup complete — all four injection statuses are live in the cluster."
