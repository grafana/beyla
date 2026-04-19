# SDK Injection Metrics Test Plan

This document provides a step-by-step test plan for validating the SDK injection metrics implementation in Beyla's webhook component.

## Prerequisites

### On Your Remote Linux Machine

1. **Docker** - For building Beyla images
2. **kubectl** - Kubernetes CLI
3. **kind** - Kubernetes in Docker (for local k8s cluster)
4. **curl** - For testing endpoints
5. **Optional: k9s** - Terminal UI for Kubernetes (highly recommended)

Install these tools:
```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/latest/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Install k9s (optional but recommended)
curl -sS https://webinstall.dev/k9s | bash
```

## Test Environment Setup

### Step 1: Create a Kind Kubernetes Cluster

```bash
# Create a new kind cluster
kind create cluster --name beyla-test

# Verify the cluster is running
kubectl cluster-info
kubectl get nodes
```

### Step 2: Install cert-manager

The webhook requires TLS certificates. cert-manager will automatically generate these.

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml

# Wait for cert-manager to be ready
kubectl wait --for=condition=Available deployment/cert-manager-webhook -n cert-manager --timeout=120s

# Verify cert-manager is running
kubectl get pods -n cert-manager
```

Expected output - all pods should be Running:
```
NAME                                       READY   STATUS    RESTARTS   AGE
cert-manager-<hash>                        1/1     Running   0          1m
cert-manager-cainjector-<hash>             1/1     Running   0          1m
cert-manager-webhook-<hash>                1/1     Running   0          1m
```

### Step 3: Build Beyla with Your Changes

```bash
# Navigate to the Beyla repository
cd /path/to/beyla

# Build the Beyla Docker image with your metrics changes
docker build -t beyla:local -f Dockerfile .

# Load the image into kind
kind load docker-image beyla:local --name beyla-test
```

### Step 4: Set Up Observability Backend (Optional but Recommended)

For a complete setup, run Grafana LGTM stack on your Linux machine:

```bash
# Pull and run Grafana LGTM (Loki, Grafana, Tempo, Mimir)
docker run -d --name lgtm \
  -p 3000:3000 \
  -p 4317:4317 \
  -p 4318:4318 \
  grafana/otel-lgtm:latest
```

Access Grafana at `http://<your-linux-machine-ip>:3000` (default credentials: admin/admin)

## Deploy Beyla Webhook

### Step 5: Deploy Beyla with Webhook and Internal Metrics Enabled

Create a custom Beyla configuration with internal metrics enabled:

```bash
cd pkg/webhook/example

# Edit beyla.yaml to enable internal metrics
# Add this to the beyla-config ConfigMap:
```

Create `beyla-test.yaml` with the following content:

```yaml
# Save this as beyla-test.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: beyla-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: beyla-config
  namespace: beyla-system
data:
  beyla-config.yml: |
    # Enable internal metrics
    internal_metrics:
      prometheus:
        port: 6060
        path: /internal/metrics

    # Discovery configuration - match specific namespaces
    discovery:
      instrument:
        # Match all pods in test-success namespace
        - k8s_namespace_name: "test-success"
        # Match all pods in test-failure namespace
        - k8s_namespace_name: "test-failure"

    # Webhook configuration
    injector:
      webhook:
        enable: true
        port: 8443
        cert_path: /etc/webhook/certs/tls.crt
        key_path: /etc/webhook/certs/tls.key
        timeout: 60s

      # SDK configuration
      host_path_volume: /var/lib/beyla/instrumentation
      sdk_package_version: v1.0.0
      manage_sdk_versions: true

      # Enable all supported SDKs
      enabled_sdks:
        - java
        - dotnet
        - nodejs
        - python

    # OTLP export configuration
    otel_traces_export:
      endpoint: http://172.17.0.1:4318
      protocol: http/protobuf

    otel_metrics_export:
      endpoint: http://172.17.0.1:4318
      protocol: http/protobuf
---
# Copy the rest of beyla.yaml or beyla_image.yaml from pkg/webhook/example/
# Make sure to:
# 1. Reference beyla:local image
# 2. Add port 6060 to the container ports for internal metrics
# 3. Expose port 6060 via a Service for easy access
```

Then merge with the example beyla.yaml:

```bash
# Use the image-based approach if your k8s is >= 1.31
kubectl apply -f beyla_image.yaml
# OR use the hostPath approach for older k8s
# kubectl apply -f beyla.yaml

# Apply your custom config
kubectl apply -f beyla-test.yaml
```

### Step 6: Create Internal Metrics Service

Create a service to expose Beyla's internal metrics:

```bash
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
```

### Step 7: Verify Beyla is Running

```bash
# Check Beyla pods
kubectl get pods -n beyla-system

# Check Beyla logs
kubectl logs -n beyla-system -l app=beyla --tail=50

# Verify webhook is registered
kubectl get mutatingwebhookconfigurations

# Check internal metrics are exposed
kubectl port-forward -n beyla-system svc/beyla-internal-metrics 6060:6060 &
curl http://localhost:6060/internal/metrics | grep beyla_sdk_injection
```

Expected metrics (should initially be zero or not present):
```
beyla_sdk_injection_attempts_total
beyla_sdk_injection_successes_total
beyla_sdk_injection_failures_total
beyla_sdk_injection_restarts_total
```

## Test Scenario 1: Successful Injection

This test validates that metrics are recorded correctly for successful SDK injection.

### Step 8: Deploy Test Application (Success Case)

Create a namespace and deploy a Java application:

```bash
# Create test namespace
kubectl create namespace test-success

# Deploy a simple Java app
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
```

### Step 9: Verify Successful Injection

```bash
# Wait for pod to be created and injected
kubectl get pods -n test-success -w

# Check if the pod was instrumented
kubectl get pod -n test-success -l app=java-app -o yaml | grep -A 5 "LD_PRELOAD"

# Check for instrumentation label
kubectl get pod -n test-success -l app=java-app -o yaml | grep "com.grafana.beyla/instrumented"

# Check internal metrics
curl http://localhost:6060/internal/metrics | grep beyla_sdk_injection
```

**Expected Results:**
- Pod should have `LD_PRELOAD` environment variable set
- Pod should have `com.grafana.beyla/instrumented` label
- Metrics should show:
  ```
  beyla_sdk_injection_attempts_total{namespace="test-success",language="java"} 1
  beyla_sdk_injection_successes_total{namespace="test-success",language="java"} 1
  beyla_sdk_injection_failures_total - should not increment for this case
  ```

## Test Scenario 2: Injection Failures

This test validates that failure metrics are recorded correctly for various error conditions.

### Test 2a: Already Instrumented

```bash
# Create a pod that's already instrumented
cat <<EOF | kubectl apply -f -
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

# Check metrics
curl http://localhost:6060/internal/metrics | grep 'beyla_sdk_injection_failures_total.*already_instrumented'
```

**Expected Result:**
```
beyla_sdk_injection_failures_total{namespace="test-success",language="java",error_type="already_instrumented"} 1
```

### Test 2b: LD_PRELOAD Conflict

```bash
# Create a pod with existing LD_PRELOAD
cat <<EOF | kubectl apply -f -
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

# Check metrics
curl http://localhost:6060/internal/metrics | grep 'beyla_sdk_injection_failures_total.*ld_preload_conflict'
```

**Expected Result:**
```
beyla_sdk_injection_failures_total{namespace="test-success",language="java",error_type="ld_preload_conflict"} 1
```

### Test 2c: No Matching Language

```bash
# Create a namespace that doesn't match our selection criteria
kubectl create namespace test-nomatch

# Deploy an app
cat <<EOF | kubectl apply -f -
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

# Check metrics - should NOT increment because namespace doesn't match
curl http://localhost:6060/internal/metrics | grep beyla_sdk_injection
```

**Expected Result:**
- No new metrics for "test-nomatch" namespace
- Only "test-success" namespace should have metrics

## Test Scenario 3: Deployment Restarts

This test validates that restart metrics are recorded when deployments are bounced.

### Step 10: Deploy an Existing Deployment for Auto-Restart

First, deploy an app WITHOUT Beyla running (so it won't be instrumented):

```bash
# Temporarily delete Beyla
kubectl delete -f beyla-test.yaml
kubectl delete -f beyla_image.yaml  # or beyla.yaml

# Deploy a Java app
kubectl create namespace test-restart
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: restart-test
  namespace: test-restart
spec:
  replicas: 1
  selector:
    matchLabels:
      app: restart-test
  template:
    metadata:
      labels:
        app: restart-test
    spec:
      containers:
      - name: java-app
        image: openjdk:11-jre-slim
        command: ["sh", "-c", "while true; do echo 'Running'; sleep 10; done"]
EOF

# Wait for pod to be running
kubectl wait --for=condition=Ready pod -l app=restart-test -n test-restart --timeout=60s
```

Now add the namespace to Beyla's config and redeploy:

```bash
# Edit beyla-test.yaml to add test-restart namespace to discovery.instrument
# Then redeploy Beyla
kubectl apply -f beyla_image.yaml  # or beyla.yaml
kubectl apply -f beyla-test.yaml

# Watch for the deployment to be restarted
kubectl get pods -n test-restart -w
```

**Expected Results:**
- Deployment should be automatically restarted (you'll see the pod recreated)
- Check restart metrics:
  ```bash
  curl http://localhost:6060/internal/metrics | grep 'beyla_sdk_injection_restarts_total'
  ```
- Expected metric:
  ```
  beyla_sdk_injection_restarts_total{namespace="test-restart"} 1
  ```

## Validation Checklist

Use this checklist to verify all metrics are working correctly:

### Metric: `beyla_sdk_injection_attempts_total`

- [ ] Increments when pod creation is intercepted
- [ ] Has correct `namespace` label
- [ ] Has correct `language` label (java, dotnet, nodejs, python)
- [ ] Increments once per enabled SDK per pod

### Metric: `beyla_sdk_injection_successes_total`

- [ ] Increments on successful injection
- [ ] Has correct `namespace` label
- [ ] Has correct `language` label
- [ ] Matches attempts when no errors occur

### Metric: `beyla_sdk_injection_failures_total`

- [ ] Increments for `already_instrumented` error
- [ ] Increments for `ld_preload_conflict` error
- [ ] Increments for `no_matching_language` error
- [ ] Increments for `missing_sdk_version` error
- [ ] Increments for `patch_generation_failed` error
- [ ] Has correct `error_type` label

### Metric: `beyla_sdk_injection_restarts_total`

- [ ] Increments when deployment is restarted
- [ ] Has correct `namespace` label
- [ ] Only increments once per deployment (no double-restarts)

## Prometheus Query Examples

If you're using Prometheus/Grafana, here are some useful queries:

```promql
# Total injection attempts by namespace
sum by (namespace) (beyla_sdk_injection_attempts_total)

# Success rate by language
sum by (language) (beyla_sdk_injection_successes_total) / sum by (language) (beyla_sdk_injection_attempts_total)

# Failure breakdown by error type
sum by (error_type) (beyla_sdk_injection_failures_total)

# Total restarts triggered
sum(beyla_sdk_injection_restarts_total)

# Failures per namespace
sum by (namespace, error_type) (beyla_sdk_injection_failures_total)
```

## Troubleshooting

### Metrics not appearing

1. Check Beyla is running:
   ```bash
   kubectl get pods -n beyla-system
   kubectl logs -n beyla-system -l app=beyla
   ```

2. Verify internal metrics endpoint:
   ```bash
   kubectl port-forward -n beyla-system svc/beyla-internal-metrics 6060:6060
   curl http://localhost:6060/internal/metrics
   ```

3. Check webhook is registered:
   ```bash
   kubectl get mutatingwebhookconfigurations
   kubectl describe mutatingwebhookconfiguration beyla-webhook
   ```

### Pods not being injected

1. Check if namespace matches discovery criteria:
   ```bash
   kubectl get configmap beyla-config -n beyla-system -o yaml
   ```

2. Check webhook logs:
   ```bash
   kubectl logs -n beyla-system -l app=beyla --tail=100 | grep -i mutate
   ```

3. Check pod events:
   ```bash
   kubectl describe pod <pod-name> -n <namespace>
   ```

### Restarts not triggering

1. Verify selection criteria is configured (deployment restarts only work when there are selectors)
2. Check if `disable_auto_restart` is set to `false`
3. Verify the pod is in a supported language (Java, .NET, Node.js)
4. Check Beyla logs for bouncer messages

## Clean Up

```bash
# Delete test namespaces
kubectl delete namespace test-success
kubectl delete namespace test-failure
kubectl delete namespace test-restart
kubectl delete namespace test-nomatch

# Delete Beyla
kubectl delete namespace beyla-system

# Delete the kind cluster
kind delete cluster --name beyla-test

# Stop LGTM container (if running)
docker stop lgtm
docker rm lgtm
```

## Expected Test Results Summary

After running all test scenarios, you should see metrics similar to:

```
# Attempts (varies based on number of SDKs enabled and pods created)
beyla_sdk_injection_attempts_total{namespace="test-success",language="java"} 3
beyla_sdk_injection_attempts_total{namespace="test-success",language="nodejs"} 0
beyla_sdk_injection_attempts_total{namespace="test-restart",language="java"} 1

# Successes
beyla_sdk_injection_successes_total{namespace="test-success",language="java"} 1
beyla_sdk_injection_successes_total{namespace="test-restart",language="java"} 1

# Failures
beyla_sdk_injection_failures_total{namespace="test-success",language="java",error_type="already_instrumented"} 1
beyla_sdk_injection_failures_total{namespace="test-success",language="java",error_type="ld_preload_conflict"} 1

# Restarts
beyla_sdk_injection_restarts_total{namespace="test-restart"} 1
```

## Next Steps

Once you've validated the metrics are working correctly:

1. Document any issues found
2. Consider adding Grafana dashboards for these metrics
3. Set up alerts for high failure rates
4. Add integration tests to CI/CD pipeline
