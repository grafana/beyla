# Beyla SDK Injection — Demo Guide

This guide walks through the `quick-test.sh` demo: what it sets up, what to watch in Grafana as it runs, and how to make live changes without tearing down the cluster.

---

## Prerequisites

| Tool | Purpose |
|---|---|
| `docker` | Build the Beyla image |
| `kubectl` | Manage the kind cluster |
| `kind` | Local Kubernetes cluster |
| `helm` | Only needed for the Grafana Cloud eBPF Beyla step |

---

## 1. Running the demo from scratch

### 1a. Set up credentials (optional but recommended)

To send metrics to Grafana Cloud, set these before running the script. Skip if you only want local validation.

```bash
# Grafana Cloud → (your stack) → Details → Prometheus section
export GRAFANA_PROM_REMOTE_WRITE_URL="https://prometheus-prod-XX-XXX.grafana.net/api/prom/push"
export GRAFANA_PROM_USERNAME="123456"          # your instance ID (numeric)
export GRAFANA_PROM_PASSWORD="glsa_xxxx..."    # API key, MetricsPublisher role
```

### 1b. Run the script

```bash
cd <repo-root>
./pkg/webhook/docs/quick-test.sh
```

The script takes roughly **8–12 minutes** end to end. Leave it running — a background pulse process keeps creating/deleting pods after setup completes.

### 1c. What to watch as it runs

The script narrates each phase. Open Grafana → Explore alongside it:

| Script phase | PromQL to run | What you should see |
|---|---|---|
| **Phase A starts** — Beyla online | `beyla_injection_pods` | `pending_restart=3` for `test-preexisting` |
| **Phase A rollout** — legacy-app restarted | same | `pending_restart` drops to 0, `instrumented` climbs to 3 |
| **Phase B** — all scenarios deployed | `beyla_injection_pods` | All four status values present simultaneously |
| **Pulse running** (ongoing) | `rate(beyla_sdk_injection_attempts_total[5m])` | Sawtooth — steady injection attempts every ~90s |

### 1d. Verify the full picture

Once setup is complete, run this query in Explore to see all statuses at once:

```promql
sum by (k8s_namespace_name, status, skip_reason) (beyla_injection_pods)
```

Expected output:

| namespace | status | skip_reason | count |
|---|---|---|---|
| test-preexisting | instrumented | | 3 |
| test-instrumented | instrumented | | 3+ |
| test-conflict | skipped | conflict | 2 |
| test-skipped | skipped | already_instrumented | 1 |
| test-unmatched | unmatched | | 2 |
| test-unmatched | instrumented | | 1 |

---

## 2. Re-establishing the port-forward

The port-forward to Beyla's metrics endpoint closes when the script exits or the terminal is interrupted. Re-open it:

```bash
BEYLA_POD=$(kubectl get pod -n default -l app=beyla -o jsonpath='{.items[0].metadata.name}')
kubectl port-forward -n default "pod/$BEYLA_POD" 9090:9090 &

# Verify it works
curl -s http://localhost:9090/internal/metrics | grep beyla_injection_pods | head -10
```

Or use the existing check script for a quick formatted view:

```bash
./pkg/webhook/docs/check.sh
```

---

## 3. Making changes and seeing results (no cluster restart needed)

All changes below take effect within one Prometheus scrape interval (~15s).

### 3a. Scale a workload — change the pod count

The state metric tracks individual pods. Scaling a Deployment changes the count immediately.

```bash
# Scale the fresh-app up to 5 pods (instrumented count rises to 5)
kubectl scale deployment/fresh-app -n test-instrumented --replicas=5

# Scale back down
kubectl scale deployment/fresh-app -n test-instrumented --replicas=3
```

Watch in Grafana:
```promql
beyla_injection_pods{k8s_namespace_name="test-instrumented", status="instrumented"}
```

### 3b. Add a new workload to an existing watched namespace

```bash
kubectl create deployment new-service \
  --namespace test-instrumented \
  --image=busybox \
  -- sh -c "while true; do sleep 30; done"
```

New pods come up through the webhook admission and land as `instrumented`. The state metric picks them up on the next scrape.

> **Note**: If Beyla is already running when you create this Deployment, the webhook mutates pods at admission time — no manual restart needed.

### 3c. Trigger the pending_restart → instrumented transition manually

Pre-existing busybox pods stay as `pending_restart` because Beyla can't detect their language via `/proc` scanning. Simulate the real-world "operator restarts pods after Beyla install" action:

```bash
# Roll all pods in a namespace through the webhook
kubectl rollout restart deployment/legacy-app -n test-preexisting

# Watch the transition in the dashboard:
# pending_restart drops → instrumented rises
```

### 3d. Add or remove a namespace from scope

Edit the ConfigMap and restart the Beyla DaemonSet. The change takes ~30s.

```bash
kubectl edit configmap beyla-config -n default
# In the editor: add or remove entries under injector.instrument

kubectl rollout restart daemonset/beyla -n default
kubectl rollout status daemonset/beyla -n default
```

**To remove a namespace from scope**: delete its entry from `instrument`. Its pods will disappear from `beyla_injection_pods` entirely on the next scrape — they go out of scope, not to `unmatched`.

**To add a new namespace**: add it to `instrument`, create the namespace, and deploy workloads. Pods created after Beyla restarts will be mutated at admission.

### 3e. Simulate a conflict scenario in a new namespace

```bash
kubectl create namespace test-conflict-2 2>/dev/null || true

# First, add this namespace to the ConfigMap (see 3d above)

kubectl create deployment conflict-demo \
  --namespace test-conflict-2 \
  --image=busybox \
  -- sh -c "while true; do sleep 30; done"

# Patch it to add a conflicting LD_PRELOAD
kubectl set env deployment/conflict-demo \
  -n test-conflict-2 \
  LD_PRELOAD=/vendor/libsecurity.so
```

On the next rollout (the `set env` triggers one), pods come up with the pre-existing LD_PRELOAD and appear as `status=skipped, skip_reason=conflict`.

### 3f. Add the inject label to an unmatched pod

The `test-unmatched` namespace uses a pod-label selector (`inject: "true"`). Pods without the label are `unmatched`. Add the label to make a pod get instrumented:

```bash
# Patch the Deployment template to add the label
kubectl patch deployment/unlabeled-app -n test-unmatched \
  --type=json \
  -p='[{"op":"add","path":"/spec/template/metadata/labels/inject","value":"true"}]'

# Pods restart, go through webhook → instrumented
# unmatched count drops by 2, instrumented count rises by 2
```

Remove it to revert:

```bash
kubectl patch deployment/unlabeled-app -n test-unmatched \
  --type=json \
  -p='[{"op":"remove","path":"/spec/template/metadata/labels/inject"}]'
```

### 3g. Watch the background pulse

The script leaves a background process running `pulse-N` pods every 90 seconds. This drives the event counters. Watch them accumulate:

```promql
# Rate of webhook admission attempts (should show regular spikes)
rate(beyla_sdk_injection_attempts_total[5m])

# Total attempts since Beyla started
beyla_sdk_injection_attempts_total
```

The pulse stops when the script's terminal session ends. Restart it manually if needed:

```bash
# One-liner that mimics the pulse loop
while true; do
  N=$RANDOM
  kubectl run "pulse-$N" --namespace test-instrumented --image=busybox \
    --restart=Never --labels="scenario=churn" -- sh -c "sleep 20" 2>/dev/null || true
  sleep 45
  kubectl delete pod "pulse-$N" --namespace test-instrumented --ignore-not-found 2>/dev/null || true
  sleep 45
done
```

---

## 4. Useful one-liners

```bash
# Current state of all injection pods (formatted)
curl -s http://localhost:9090/internal/metrics \
  | grep 'beyla_injection_pods{' | sort

# Summary counts by status
curl -s http://localhost:9090/internal/metrics \
  | grep 'beyla_injection_pods{' \
  | grep -oP 'status="[^"]+"' | sort | uniq -c

# All pods and whether they have our LD_PRELOAD
for ns in test-preexisting test-instrumented test-conflict test-skipped test-unmatched; do
  echo "--- $ns ---"
  kubectl get pods -n "$ns" -o jsonpath=\
'{range .items[*]}{.metadata.name}{"\t"}{range .spec.containers[*]}{range .env[*]}{.name}={.value}{" "}{end}{end}{"\n"}{end}' \
  | grep -E "LD_PRELOAD|^"
done

# Check Beyla logs for webhook decisions
kubectl logs -n default -l app=beyla --tail=50 | grep -E "mutating|skip|inject|instrument"

# Check Prometheus remote-write health (if running)
kubectl logs -n default prometheus-remote-write | grep -E "err|fail|remote|write" | tail -20
```

---

## 5. Tearing down

```bash
kind delete cluster --name beyla-test
```

This removes the cluster and all workloads. The Beyla image `beyla:local` remains in Docker — the next run skips the build step if you add `docker build` caching or pre-load the image.
