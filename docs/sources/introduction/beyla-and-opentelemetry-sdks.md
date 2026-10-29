---
title: Compare Beyla and OpenTelemetry SDKs
menuTitle: Beyla and SDKs
description: Compare Grafana Beyla eBPF auto-instrumentation with OpenTelemetry SDKs by language and framework, and decide when to use Beyla, SDKs, or both.
weight: 300
keywords:
  - Beyla
  - eBPF
  - OpenTelemetry
  - SDK
---

# Compare Beyla and OpenTelemetry SDKs

Beyla and OpenTelemetry SDKs both produce metrics and traces for your services, but they work in different ways.
Beyla uses eBPF to instrument services without code changes.
OpenTelemetry SDKs and agents run inside your application and can capture internal, framework, and business detail.
You can also use both.

To decide what to use for each service, review when each option fits, then check how well Beyla supports your language.

## When to use Beyla

Use Beyla first when you need:

- A zero-code rollout
- RED metrics and service graphs
- Broad baseline visibility across many services
- Coverage for services where an SDK rollout is hard or impossible

## When to use OpenTelemetry SDKs or agents

Use OpenTelemetry SDKs or agents when you need:

- The most reliable distributed tracing
- Internal spans and framework or library detail
- Trace-to-log correlation through your logging framework.
  Beyla also supports trace-to-log correlation, including for SDK-instrumented services where the SDK doesn't provide it.
- Runtime metrics
- Custom span attributes, events, and business telemetry

## When to use Beyla and SDKs together

In environments with many languages, a practical pattern is to run Beyla on every service, and add SDKs where you need more detail.
Use Beyla and SDKs together when you want:

- Beyla to provide baseline metrics and service graphs
- SDKs to provide deep traces, log correlation, runtime metrics, or custom telemetry on the services that need them

For a service that already uses an OpenTelemetry SDK, use the SDK for traces.
By default, Beyla detects services that export OpenTelemetry traces or metrics, and stops generating that signal for them.
If the SDK exports only traces, Beyla still generates RED metrics for the service.
If you change this default, verify the behavior before you run Beyla tracing and SDK tracing for the same service.
For details, refer to [Configure Beyla service discovery][exclude-otel].

If Beyla also generates span metrics or service graphs, set `span.metrics.skip=true` in `OTEL_RESOURCE_ATTRIBUTES` on the SDK service to prevent the Collector or Tempo from generating duplicate metrics from the SDK traces.
Beyla adds this attribute to its own traces when it also exports span metrics.

## Language and framework support

Use Beyla RED metrics for all of the following languages and frameworks.
The choice between Beyla and an OpenTelemetry SDK depends on how well Beyla traces your language.

### Beyla traces recommended

Beyla tracing is the recommended default for Go:

- **Go (HTTP, HTTP/2, HTTPS, and gRPC)**: Go is the strongest case for eBPF tracing, and Beyla provides zero-code tracing for Go HTTP, HTTP/2, and gRPC.
  OpenTelemetry SDK tracing for Go has more limitations than Beyla tracing.
  You can add the Go OpenTelemetry SDK for deeper application-level detail.

### Beyla traces supported with limitations

For these languages, OpenTelemetry SDKs are the recommended default for traces.
Validate Beyla traces before you rely on them in production, especially for asynchronous frameworks.
Validate SDK traces too: SDK coverage varies by language and framework, and if no SDK instrumentation exists for your framework, the SDK collects no data.

- **Java (standard servlet or thread-pool models)**: Beyla tracing can work, but SDK traces are more robust.
- **Node.js HTTP**: Beyla tracing works reasonably well, but SDKs provide richer spans and stronger log and runtime correlation.
- **Python HTTP and `asyncio`**: Beyla supports Python `asyncio`, but asynchronous context propagation has framework-specific limitations.
  Add the Python OpenTelemetry SDK for richer spans and stronger runtime correlation.
- **Ruby**: Beyla support is reasonable, but asynchronous and framework coverage is narrower than with SDK tracing.
- **.NET**: Beyla tracing works well when the .NET service isn't the first service in the call chain.
  If it's the entry point, tracing may not work correctly.

### Beyla traces not recommended

Don't use Beyla traces for the following frameworks:

- **Java reactive or thread-switching frameworks**: Reactive Java isn't a good fit for eBPF trace correlation.
  Beyla may emit stand-alone spans that aren't attached to the correct trace.
  Use an OpenTelemetry SDK for traces.

## Next steps

- [Compare Beyla and OpenTelemetry eBPF Instrumentation][obi]
- [Beyla requirements and limitations][requirements]
- [Set up Beyla][setup]
- [Beyla quickstart guides][quickstart]

[exclude-otel]: ../../configure/service-discovery/#exclude-otel-instrumented-services
[obi]: ../obi/
[requirements]: ../requirements/
[setup]: ../../setup/
[quickstart]: ../../quickstart/
