# JVM Runtime Metrics From HotSpot Probes

Date: 2026-06-10

## Context

Beyla issue `grafana/beyla#1608` asks whether Beyla can integrate a Rust PoC from
`/Users/abalaian/github/REASY/jheapusage` that collects Java heap usage from eBPF.
The issue discussion points toward adding the core probe code to OBI's generic
tracer and wiring it through Beyla.

The PoC has two probe families:

- HotSpot USDT probes `hotspot:mem__pool__gc__begin` and
  `hotspot:mem__pool__gc__end`, which report per-memory-pool values around GC.
- A uprobe on the hidden HotSpot C++ function
  `GCTracer::report_gc_heap_summary`, which reports aggregate heap usage.

This design implements both paths. The aggregate uprobe is optional per process:
when Beyla can resolve `GCTracer::report_gc_heap_summary` in `libjvm.so`, it
attaches and exports aggregate heap usage; when the symbol is absent, Beyla
continues with USDT memory-pool metrics and normal application instrumentation.

Current Beyla integration uses the OBI branch `jvm-runtime-metrics` from
`REASY/opentelemetry-ebpf-instrumentation` while upstream review is pending.
Beyla's `.obi-src` submodule is pinned to the pushed OBI PR head, and Beyla's
`vendor/go.opentelemetry.io/obi` is synced from that submodule because Beyla's
Docker integration image builds with `go build -mod vendor`.

## Goals

- Export JVM memory pool metrics from Beyla without requiring a Java agent or
  application changes.
- Use OpenTelemetry JVM semantic convention metric names where possible:
  `jvm.memory.used`, `jvm.memory.committed`, `jvm.memory.limit`, and
  `jvm.memory.used_after_last_gc`.
- Export aggregate heap usage from `GCTracer::report_gc_heap_summary` when the
  target JVM exposes the symbol.
- Support Prometheus and OTEL exporters consistently with existing Beyla metrics.
- Allow users to disable the functionality explicitly.
- Allow users to control sampling so GC-heavy applications can reduce event cost.
- Make the implementation testable without requiring a live JVM for most tests.

## Non-Goals

- Do not port Rust user-space code into Beyla.
- Do not try to replace metrics already emitted by an injected OpenTelemetry Java
  agent. This feature is for eBPF-only JVM runtime visibility.
- Do not collect JVM thread/class/CPU metrics in this slice.

## Existing Configuration Pattern

Beyla and OBI already use `metrics.features` as the primary on/off switch for
metric families. Examples include `application`, `application_process`,
`network`, and `stats`. Exporters must also be enabled; otherwise the pipeline
does not emit metrics.

Some eBPF behavior also has feature-specific controls when the switch affects
runtime behavior rather than metric selection. Examples include Java agent
injection `javaagent.enabled`, NodeJS `nodejs.enabled`, network sampling
`network.sampling`, and eBPF-specific knobs under `ebpf`.

This feature should follow both patterns:

- `metrics.features` controls whether runtime metrics are exported.
- A JVM runtime-metrics config block controls probe enablement and sampling.

## User-Facing Configuration

Add a new metric feature:

```yaml
metrics:
  features:
    - application
    - application_jvm
```

Add a JVM runtime metrics config block:

```yaml
jvm_runtime_metrics:
  enabled: true
  sampling_interval: 1s
```

Environment variables:

- `BEYLA_JVM_RUNTIME_METRICS_ENABLED`
- `BEYLA_JVM_RUNTIME_METRICS_SAMPLING_INTERVAL`

Semantics:

- `enabled: false` hard-disables probe attachment and exporter setup, even if
  `application_jvm` is listed in `metrics.features`.
- `enabled: true` permits JVM runtime metrics when the feature and a metrics
  exporter are enabled.
- `sampling_interval: >0` rate-limits events in BPF per process, pool, and GC
  phase. OBI currently validates this field as strictly positive when
  `enabled: true`.
- Defaults: `enabled: false`, `sampling_interval: 1s`.

Rationale:

- Default-off avoids surprising users with extra runtime probes.
- `metrics.features` stays the consistent Beyla metric-family switch.
- The explicit `enabled` boolean gives operators a hard kill switch that is easy
  to reason about in Helm, Alloy, and incident response.
- Interval-based sampling matches the PoC and is easier to apply in BPF than
  probability-based sampling while preserving recent values per memory pool.

## Architecture

### Probe Placement

Implement the BPF code in the OBI source tree beside the generic tracer BPF
programs, following the issue guidance. In this Beyla branch, `.obi-src` is
pinned to the OBI JVM runtime metrics branch and the vendored/generated OBI
artifacts are synced from it.

The implementation adds:

- BPF event structs for JVM memory pool events.
- BPF event structs for aggregate JVM heap summary events.
- Two USDT programs:
  - `hotspot_mem_pool_gc_begin`
  - `hotspot_mem_pool_gc_end`
- One optional uprobe program:
  - `report_gc_heap_summary`
- Dedicated ring buffers compatible with the generic tracer reader.
- Read-only config constants:
  - `jvm_runtime_metrics_enabled`
  - `jvm_sampling_interval_ns`

The BPF program should not emit events when disabled. If disabled at user-space
configuration time, Beyla/OBI should also avoid attaching the USDT probes and
the aggregate uprobe.

The implemented transport uses two dedicated ring buffers:

- `jvm_gc_heap_summary_events` for aggregate heap summary samples.
- `jvm_mem_pool_gc_events` for memory-pool USDT samples.

It also uses two LRU hash maps for interval sampling:

- `jvm_heap_summary_samples`.
- `jvm_mem_pool_samples`.

### Process Selection

Attach only to processes discovered as HotSpot/OpenJDK JVMs:

- Use existing language detection that identifies Java by `libjvm.so`.
- Resolve the loaded `libjvm.so` mapping from `/proc/<pid>/maps`.
- Attach USDT probes to that library mapping for the specific PID. OBI parses
  `.note.stapsdt` notes, builds architecture-specific argument specs for x86_64
  and arm64, writes them into `obi_usdt_specs`, maps absolute probe IPs to spec
  IDs in `obi_usdt_ip_to_spec_id`, and attaches uprobes at the resolved USDT
  instruction addresses.
- Search `libjvm.so` regular and dynamic ELF symbols for a function whose name
  contains `report_gc_heap_summary`, then attach the aggregate uprobe by offset
  to the resolved full mangled symbol. The PoC observed the mangled name
  `_ZNK8GCTracer22report_gc_heap_summaryEN6GCWhen4TypeERK13GCHeapSummary` on
  Java 11 and Java 21.
- Skip non-HotSpot JVMs if required probes are unavailable.
- Treat both JVM probe families as optional. Missing memory-pool USDT probes
  disables memory-pool JVM metrics for that process. Missing
  `report_gc_heap_summary` disables only aggregate heap metrics for that
  process. In both cases, unrelated application instrumentation continues.

OpenJ9 support is out of scope for the first slice unless it exposes equivalent
compatible probes.

### Data Model

BPF event fields:

Memory pool event:

- monotonic kernel timestamp from `bpf_ktime_get_ns`, converted to wall-clock
  time in Go using OBI's monotonic clock helper
- host PID/TID
- namespace PID/TID and PID namespace ID
- memory manager name
- memory pool name
- `init_size`
- `used`
- `committed`
- `max_size`
- phase: `before` or `after`

Aggregate heap summary event:

- monotonic kernel timestamp from `bpf_ktime_get_ns`, converted to wall-clock
  time in Go using OBI's monotonic clock helper
- host PID/TID
- namespace PID/TID and PID namespace ID
- phase: `before` or `after`
- `used`

Use fixed-size strings, likely 64 bytes as in the PoC. Truncate safely and ensure
null termination.

The aggregate uprobe reads the `used` field from HotSpot's `GCHeapSummary`
argument using a small C layout struct. The implementation follows the PoC's
Java 11/21 layout assumption and keeps the aggregate uprobe optional so stripped
or layout-incompatible JDKs lose only the aggregate metric. The uprobe also
skips the `G1 Main Marker` thread to avoid duplicate or misleading G1 samples.

### Metric Mapping

For each event:

Memory pool event:

- `jvm.memory.used`: record `used`
- `jvm.memory.committed`: record `committed`
- `jvm.memory.limit`: record `max_size` when `max_size != UINT64_MAX`
- `jvm.memory.used_after_last_gc`: record `used` only for `after`

Attributes:

- `jvm.memory.pool.name`: memory pool name
- `jvm.memory.type`: `heap` or `non_heap`

Pool type inference:

- Prefer a deterministic mapping from common HotSpot pool names:
  - heap: names containing `Eden`, `Survivor`, `Old`, `Tenured`, `Young`
  - non_heap: names containing `Metaspace`, `Code`, `Compressed Class`
- If unknown, keep `jvm.memory.type` as an empty value. The exporters always
  expose the attribute/label so the metric shape remains stable.

Prometheus names follow Beyla's existing conversion style:

- `jvm_memory_used_bytes`
- `jvm_memory_committed_bytes`
- `jvm_memory_limit_bytes`
- `jvm_memory_used_after_last_gc_bytes`

Aggregate heap summary event:

- OTEL: `beyla.jvm.heap.used`
- Prometheus: `beyla_jvm_heap_used_bytes`
- Unit: `By`
- Type:
  - OTEL pool metrics use current-value `Int64UpDownCounter` wrappers.
  - OTEL aggregate heap uses `Int64Gauge`.
  - Prometheus uses gauges.
- Attributes:
  - `jvm.gc.phase`: `before` or `after`

Rationale: OpenTelemetry has stable pool-level JVM memory metrics, but no exact
standard metric for the aggregate `GCHeapSummary` value. Exporting it as a Beyla
extension avoids mixing pool-level and aggregate time series under the same
Prometheus metric with incompatible label sets.

### Export Pipeline

Add a runtime metrics subpipeline parallel to the existing process metrics
subpipeline:

1. Generic tracer emits JVM runtime events.
2. A typed parser converts ring buffer records into Go `JVMRuntimeEvent`
   values.
3. The generic tracer decorates events by namespace PID and PID namespace ID
   using the current PID-to-service map.
4. OTEL and Prometheus JVM runtime reporters observe event batches and keep the
   latest metric values with normal Beyla resource/service attributes.

The pipeline should be active only when:

- a metrics exporter is enabled,
- `metrics.features` includes `application_jvm`, and
- `jvm_runtime_metrics.enabled` is true.

Per-service feature overrides should work like existing app/process features:
if a service discovery selector disables `application_jvm`, exporters drop
events from that service. Probe attachment is currently controlled by the global
`jvm_runtime_metrics.enabled` setting, not by per-service feature filtering.

Beyla's top-level `jvm_runtime_metrics` config is copied into the OBI config via
`Config.AsOBI()`. Beyla creates a JVM runtime event queue when
`jvm_runtime_metrics.enabled` is true, passes it into OBI's appolly pipeline,
and assigns it to each process tracer before `Run`. Generated OBI integration
tests are transformed into Beyla's `internal/testgenerated` tree and use Beyla
environment variables such as `BEYLA_CONFIG_PATH` and `BEYLA_PROMETHEUS_PORT`.

### Sampling

Sampling is interval-based, not probabilistic.

BPF keeps one LRU hash map for memory-pool events keyed by:

- namespace PID
- memory manager name
- memory pool name
- phase (`before` or `after`)

The map value is `last_reported_timestamp_ns`.

For each event:

- If no key exists, submit and update.
- If `now - last_reported_timestamp_ns >= sampling_interval_ns`, submit and
  update.
- Otherwise drop.

This preserves regular updates for each pool and avoids one noisy pool starving
another. The implemented map size is 4096 entries.

The aggregate heap uprobe uses independent last-reported timestamps per
namespace PID and phase. This prevents a high-frequency `before` series from
suppressing `after` values.

The BPF helper treats `jvm_sampling_interval_ns == 0` as "report every matching
event", but OBI config validation currently rejects zero when
`jvm_runtime_metrics.enabled` is true. The user-facing contract is therefore a
strictly positive interval unless validation is intentionally relaxed later.

## Testability

### Unit Tests

Implemented OBI unit coverage includes:

- Config defaults, YAML/env parsing, and positive `sampling_interval`
  validation.
- Raw JVM payload decoding for aggregate heap and memory-pool events, including
  invalid/truncated payloads and fixed-size string decoding.
- Memory-pool event expansion into `used`, `committed`, optional `limit`, and
  `used_after_last_gc` only for `after`.
- Suppression of `jvm.memory.limit` when HotSpot reports `UINT64_MAX`.
- Pool type inference for common heap and non-heap pools, including ZGC,
  Shenandoah, Epsilon, Metaspace, Code Cache, and unknown pools.
- OTEL and Prometheus JVM runtime reporter behavior, including
  `application_jvm` feature filtering.
- Generic tracer behavior for enabled/disabled JVM event readers and exposed
  HotSpot USDT probe descriptors.

### BPF and Loader Tests

Implemented coverage includes:

- BPF generation through OBI's bpf2go path for the generic tracer.
- Generated structs and map/program fields for both JVM ring buffers, sampling
  maps, USDT spec maps, and aggregate uprobe program.
- Symbol matching by substring for `report_gc_heap_summary`.
- Optional uprobe behavior for missing aggregate heap symbols.
- Optional USDT behavior for missing HotSpot memory-pool probes.
- JVM runtime event parsing/decorating without log scraping in OBI tests.

Verifier load coverage should continue to run through the same privileged Linux
CI/test path used by existing eBPF tests.

### Integration Tests

Implemented privileged integration coverage uses a small HotSpot Java
application with deterministic GC pressure:

- Start OpenJDK HotSpot app with deterministic allocation and GC pressure.
- Run OBI/Beyla with:
  - target PID or discovery selector for the app,
  - Prometheus exporter,
  - `metrics.features: [application_jvm]`,
  - `jvm_runtime_metrics.enabled: true`,
  - short sampling interval.
- Assert that Prometheus scrape includes
  `jvm_memory_committed_bytes{jvm_memory_pool_name!=""}` with the expected
  service labels.
- Assert that Prometheus scrape includes
  `beyla_jvm_heap_used_bytes{jvm_gc_phase=~"before|after"}` with the expected
  service labels when the tested JDK exposes `report_gc_heap_summary`.
- Run Weaver validation and require zero actionable violations.

Remaining desired integration coverage:

- A disabled-mode case with `jvm_runtime_metrics.enabled=false` that asserts no
  JVM runtime metrics are exported and JVM probes are not attached.
- A high-volume sampling case that asserts exported updates are bounded relative
  to `sampling_interval`.
- A missing-symbol or stripped-JDK case that proves aggregate heap absence does
  not fail memory-pool metrics.

## Risks and Mitigations

- **Probe availability:** Not every JVM distribution enables the expected USDT
  probes. Treat missing probes as feature unavailability for that process, log at
  debug/info, and continue instrumenting the service normally.
- **Config validation mismatch:** BPF supports a zero sampling interval, but OBI
  validation currently rejects `sampling_interval <= 0` when the feature is
  enabled. Beyla's validation path should be kept aligned with OBI's full config
  validation so invalid JVM runtime settings fail early.
- **Overhead on GC-heavy workloads:** Default off and interval sampling limit
  overhead.
- **Cardinality:** Memory pool and manager names are low-cardinality per JVM.
  Avoid labels such as thread ID or raw JVM command line on runtime metrics.
- **Semantic mismatch:** USDT begin/end values are GC-adjacent, not continuous
  polling. Use `jvm.memory.used_after_last_gc` only for `after`; use the other
  gauges as latest observed pool values, and document that updates occur at GC
  events.
- **HotSpot layout drift:** Aggregate heap usage depends on the `GCHeapSummary`
  memory layout. Keep the layout isolated in a small BPF struct/helper, cover it
  with documentation/tests, and make the uprobe optional per process.
- **Hidden symbol availability:** `report_gc_heap_summary` is local/hidden on
  known Java 11/21 HotSpot builds. Resolve it from regular ELF symbols and attach
  by offset. If a JDK build strips the symbol, skip only aggregate heap metrics.
- **USDT argument support:** The generic USDT parser supports the HotSpot memory
  pool probes on x86_64 and arm64. Other architectures or unsupported argument
  forms should fail the optional USDT probe attachment without failing unrelated
  instrumentation.
- **Duplicate metrics with Java agent:** If Beyla detects an OTel Java agent and
  runtime metrics are enabled, it should still be possible to export, but docs
  should warn about duplicate JVM metrics. A later enhancement can auto-disable
  runtime metrics when SDK JVM metrics are detected.
- **Public docs gap:** Public Beyla documentation under `docs/sources` still
  needs user-facing documentation for `jvm_runtime_metrics`, `application_jvm`,
  and the emitted JVM runtime metrics.

## Decisions

- Feature name: use `application_jvm`. It matches the current implementation's
  JVM-only scope and avoids implying non-JVM runtime coverage.
- Config location: use top-level `jvm_runtime_metrics`. Nesting under `java`
  would be easy to confuse with Java agent injection.
- Unknown pool type behavior: emit an empty `jvm.memory.type` value. The OTel
  convention recommends `heap` and `non_heap`; the current implementation keeps
  the metric label/attribute set stable without inventing a value.
- Aggregate heap metric name: use Beyla extension metric
  `beyla.jvm.heap.used` / `beyla_jvm_heap_used_bytes`, not `jvm.memory.used`,
  because the source is aggregate `GCHeapSummary`, not a memory pool.

## Implementation Notes

- Do the OBI implementation first, then vendor/regenerate into Beyla.
- Avoid reusing the Rust PoC's `runtime.jvm.*` metric prefix.
- Ensure the generated docs schema includes the new feature and config fields.
- While OBI PR review is pending, Beyla's feature branch may temporarily point
  `.obi-src` at the REASY fork. Before upstreaming Beyla, switch the submodule
  URL and gitlink back to a Grafana OBI commit that contains the merged feature.
