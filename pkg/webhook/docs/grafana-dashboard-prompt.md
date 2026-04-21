# Grafana Assistant Prompt — Beyla SDK Injection Dashboard

> Paste the block below directly into the Grafana Assistant.

---

Create a Grafana dashboard called **"Beyla SDK Injection — Coverage"** using the following Prometheus metrics. I'll describe each panel I want, the exact queries to use, and the layout.

**IMPORTANT — known crash to avoid**: Do NOT use a transformation type called "Transformation" — it does not exist and crashes the editor unrecoverably. The only valid transformation IDs are: `reduce`, `filterFieldsByName`, `renameByRegex`, `filterByRefId`, `filterByValue`, `organize`, `joinByField`, `seriesToRows`, `concatenate`, `calculateField`, `labelsToFields`, `groupBy`, `sortBy`, `merge`, `histogram`, `rowsToFields`, `configFromData`, `prepareTimeSeries`, `convertFieldType`, `spatial`, `fieldLookup`, `extractFields`, `heatmap`, `groupingToMatrix`, `limit`, `joinByLabels`, `regression`, `partitionByValues`, `formatString`, `groupToNestedTable`, `formatTime`, `timeSeriesTable`, `transpose`.

---

## Metric reference

### State metric (gauge, emitted per scrape)
```
beyla_injection_pods
```
Labels:
- `k8s_namespace_name` — Kubernetes namespace
- `k8s_workload_kind` — `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `Pod`, etc.
- `k8s_workload_name` — workload name
- `k8s_node_name` — node this Beyla DaemonSet pod runs on
- `status` — one of: `instrumented`, `pending_restart`, `skipped`, `unmatched`
- `skip_reason` — only populated when `status="skipped"`: `conflict`, `already_instrumented`, `unsupported_language`, `missing_sdk_version`

Because Beyla is a DaemonSet, each node emits its own slice of pods. Aggregate across nodes with `sum by (...)`.

### Event counters (cumulative, reset on restart)
```
beyla_sdk_injection_attempts_total{namespace, language}
beyla_sdk_injection_successes_total{namespace, language}
beyla_sdk_injection_failures_total{namespace, language, error_type}
beyla_sdk_injection_restarts_total{namespace}
```

---

## Dashboard variables

Add these template variables at the top of the dashboard:

1. **`$namespace`** — multi-value, query: `label_values(beyla_injection_pods, k8s_namespace_name)`, label: "Namespace", include All option
2. **`$cluster`** — single-value, query: `label_values(beyla_injection_pods, cluster)`, label: "Cluster" (if the `cluster` external label is present from Prometheus config)

---

## Row 1 — Summary stats (single-row of Stat panels)

### Panel 1 — Total instrumented pods
- Type: **Stat**
- Query:
  ```promql
  sum(beyla_injection_pods{status="instrumented", k8s_namespace_name=~"$namespace"})
  ```
- Title: "Instrumented"
- Color: green threshold at 1
- Unit: short

### Panel 2 — Pending restart
- Type: **Stat**
- Query:
  ```promql
  sum(beyla_injection_pods{status="pending_restart", k8s_namespace_name=~"$namespace"})
  ```
- Title: "Pending Restart"
- Color: yellow/orange (these pods matched a selector but haven't been bounced yet)
- Unit: short

### Panel 3 — Skipped pods
- Type: **Stat**
- Query:
  ```promql
  sum(beyla_injection_pods{status="skipped", k8s_namespace_name=~"$namespace"})
  ```
- Title: "Skipped"
- Color: orange threshold at 1

### Panel 4 — Unmatched pods
- Type: **Stat**
- Query:
  ```promql
  sum(beyla_injection_pods{status="unmatched", k8s_namespace_name=~"$namespace"})
  ```
- Title: "Unmatched (in scope, no selector)"
- Color: gray

### Panel 5 — Instrumentation coverage %
- Type: **Stat**
- Query:
  ```promql
  100 * sum(beyla_injection_pods{status="instrumented", k8s_namespace_name=~"$namespace"})
  /
  sum(beyla_injection_pods{k8s_namespace_name=~"$namespace"})
  ```
- Title: "Coverage"
- Unit: percent (0–100)
- Thresholds: red < 50, yellow < 80, green >= 80

---

## Row 2 — Status over time

### Panel 6 — Injection status over time (stacked area)
- Type: **Time series**, display mode: **stacked area**
- Queries (one per status, give each a legend override):
  ```promql
  # A
  sum(beyla_injection_pods{status="instrumented", k8s_namespace_name=~"$namespace"})
  # B
  sum(beyla_injection_pods{status="pending_restart", k8s_namespace_name=~"$namespace"})
  # C
  sum(beyla_injection_pods{status="skipped", k8s_namespace_name=~"$namespace"})
  # D
  sum(beyla_injection_pods{status="unmatched", k8s_namespace_name=~"$namespace"})
  ```
- Legend overrides: A → "Instrumented" (green), B → "Pending Restart" (yellow), C → "Skipped" (orange), D → "Unmatched" (gray)
- Title: "Pod injection status over time"

---

## Row 3 — Breakdown by namespace

### Panel 7 — Instrumented pods by namespace (bar chart)
- Type: **Bar chart**
- Query:
  ```promql
  sum by (k8s_namespace_name) (
    beyla_injection_pods{status="instrumented", k8s_namespace_name=~"$namespace"}
  )
  ```
- Orientation: horizontal
- Title: "Instrumented pods by namespace"

### Panel 8 — Status breakdown by namespace (table)
- Type: **Table**
- Single query (one series per namespace+status combination):
  ```promql
  sum by (k8s_namespace_name, status) (
    beyla_injection_pods{k8s_namespace_name=~"$namespace"}
  )
  ```
- Transformations (apply in this order):
  1. `labelsToFields` — field: `status` (pivots status values into separate columns)
  2. `organize` — rename `k8s_namespace_name` → "Namespace"; rename each status column to title-case
- Title: "Status by namespace"
- Note: use a **single query** — do NOT use multiple queries with merge here, that path crashes the editor.

---

## Row 4 — Skip reason breakdown

### Panel 9 — Skipped pods by reason (pie chart)
- Type: **Pie chart**
- Query:
  ```promql
  sum by (skip_reason) (
    beyla_injection_pods{status="skipped", k8s_namespace_name=~"$namespace"}
  )
  ```
- Legend: use `skip_reason` label
- Title: "Skip reasons"

### Panel 10 — Skipped pods detail (table)
- Type: **Table**
- Query:
  ```promql
  sort_desc(
    sum by (k8s_namespace_name, k8s_workload_kind, k8s_workload_name, skip_reason) (
      beyla_injection_pods{status="skipped", k8s_namespace_name=~"$namespace"}
    )
  )
  ```
- Show columns: `k8s_namespace_name`, `k8s_workload_kind`, `k8s_workload_name`, `skip_reason`, `Value`
- Rename "Value" → "Count"
- Title: "Skipped workloads — detail"

---

## Row 5 — Webhook event counters

### Panel 11 — Injection attempt rate (time series)
- Type: **Time series**
- Query:
  ```promql
  sum by (namespace) (rate(beyla_sdk_injection_attempts_total{namespace=~"$namespace"}[5m]))
  ```
- Title: "Webhook attempts/sec by namespace"
- Unit: ops/s (short)

### Panel 12 — Success vs failure rate (time series)
- Type: **Time series**
- Queries:
  ```promql
  # A — successes
  sum(rate(beyla_sdk_injection_successes_total{namespace=~"$namespace"}[5m]))
  # B — failures
  sum(rate(beyla_sdk_injection_failures_total{namespace=~"$namespace"}[5m]))
  ```
- Legend: A → "Successes" (green), B → "Failures" (red)
- Title: "Webhook success vs failure rate"

### Panel 13 — Failure breakdown by error type (bar chart)
- Type: **Bar chart**
- Query:
  ```promql
  sum by (error_type) (
    increase(beyla_sdk_injection_failures_total{namespace=~"$namespace"}[$__range])
  )
  ```
- Title: "Failures by error type (over selected time range)"
- Orientation: horizontal

---

## Layout suggestion

- Row 1 (stats): panels 1–5 in a single row, equal width
- Row 2 (time series): panel 6 full width
- Row 3 (namespace): panel 7 left half, panel 8 right half
- Row 4 (skip reasons): panel 9 left third, panel 10 right two-thirds
- Row 5 (webhook events): panels 11, 12, 13 in equal thirds

Set the default time range to **Last 1 hour**, refresh interval **30s**.

---

## Notes for the assistant

- The `beyla_injection_pods` metric is a gauge (not a counter) — it represents current state, not accumulated events. Do not use `rate()` or `increase()` on it.
- Each Beyla DaemonSet pod emits metrics only for pods on its own node. The `sum by (...)` aggregation across nodes is essential — do not show per-node breakdowns unless the user specifically requests them.
- `skip_reason` is only populated when `status="skipped"`. For all other status values it is an empty string — filter it out where it would clutter the visualization.
- The event counters (`beyla_sdk_injection_*_total`) reset when Beyla restarts. Use `rate()` for rate panels and `increase()` over a time range for totals.
