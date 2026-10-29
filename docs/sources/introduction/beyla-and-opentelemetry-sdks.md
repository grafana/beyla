---
title: Choose between Beyla and OpenTelemetry SDKs
menuTitle: Beyla and OpenTelemetry SDKs
description: Compare Grafana Beyla eBPF auto-instrumentation with OpenTelemetry SDKs by language and framework, and decide when to use Beyla, SDKs, or both.
weight: 300
keywords:
  - Beyla
  - eBPF
  - OpenTelemetry
  - SDK
---

# Choose between Beyla and OpenTelemetry SDKs

Beyla and OpenTelemetry SDKs both produce metrics and traces for your services, but they work in different ways.
Beyla instruments services from outside the application process, with no code changes.
OpenTelemetry SDKs and language agents run inside your application and can capture internal, framework, and business detail.
Many teams use both.

Use the compatibility matrix and guidance on this page to decide which approach fits each of your services.

## Compatibility matrix

The matrix uses the following ratings:

- _Recommended_: Best default choice
- _Supported with limitations_: Works, but has important limitations
- _Not recommended_: Use another approach

{{< fixed-table >}}

| Technology | Beyla: RED metrics | Beyla: traces | OpenTelemetry SDKs: traces | Notes |
| --- | --- | --- | --- | --- |
| **Baseline (any service)** | Recommended | Supported with limitations | Recommended | Beyla is strongest as a zero-code baseline layer for RED metrics and service graphs. SDKs remain the default recommendation for detailed distributed tracing. |
| **Service already using an OpenTelemetry SDK** | Recommended | Not recommended | Recommended | By default, Beyla detects services that export OpenTelemetry traces or metrics, and stops generating that signal for them. If Beyla also generates span metrics or service graphs, set `span.metrics.skip=true` in `OTEL_RESOURCE_ATTRIBUTES` on the SDK service to prevent the Collector or Tempo from generating duplicate metrics from the SDK traces. Beyla adds this attribute to its own traces when it also exports span metrics. |
| **Go HTTP / HTTP2 / HTTPS** | Recommended | Recommended | Supported with limitations | Go is a first-class case for eBPF tracing. Beyla provides zero-code instrumentation for Go HTTP, HTTP2, and gRPC. You can also add the Go OpenTelemetry SDK for deeper application-level detail. |
| **Go gRPC** | Recommended | Recommended | Supported with limitations | Go gRPC is one of the strongest Beyla tracing cases. |
| **Java HTTP (standard servlet / thread-pool)** | Recommended | Supported with limitations | Recommended | Beyla tracing can work for Java in standard thread-pool models, but SDK traces are still the more robust default. |
| **Java reactive / thread-switching** | Recommended | Not recommended | Recommended | Reactive Java isn't a good fit for eBPF trace correlation. Beyla may emit stand-alone spans that aren't attached to the correct trace. |
| **Node.js HTTP** | Recommended | Supported with limitations | Recommended | Beyla tracing works reasonably well for Node.js, but SDKs still provide richer spans and stronger log and runtime correlation. |
| **Python HTTP** | Recommended | Supported with limitations | Recommended | Python tracing support is reasonable, but asynchronous context propagation has framework-specific limitations. |
| **Python asynchronous** | Recommended | Supported with limitations | Recommended | Beyla supports Python `asyncio`. Use Beyla for zero-code coverage, and add the Python OpenTelemetry SDK for richer spans and stronger runtime correlation. |
| **Ruby** | Recommended | Supported with limitations | Recommended | Ruby support is reasonable, but asynchronous and framework coverage is narrower than with SDK tracing. |
| **.NET** | Recommended | Supported with limitations | Recommended | Beyla tracing works well when the .NET service isn't the first in the call chain. If it's the entry point, tracing may not work correctly. Validate behavior before you rely on Beyla traces for .NET in production. |
| **Mixed polyglot environment** | Recommended | Supported with limitations | Recommended where available | A practical pattern is Beyla everywhere for baseline metrics and service graphs, then SDKs on the services where you need deep tracing, log correlation, runtime metrics, or custom telemetry. |

{{< /fixed-table >}}

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
- Trace-to-log correlation.
  Beyla also supports trace-to-log correlation, including for SDK-instrumented services where the SDK doesn't provide it.
- Runtime metrics
- Custom span attributes, events, and business telemetry

## When to use Beyla and SDKs together

Use Beyla and SDKs together when you want:

- Beyla to provide baseline metrics and service graphs
- SDKs to provide deep traces

## Considerations

Keep the following in mind when you plan your instrumentation:

- For services not written in Go, especially asynchronous or reactive frameworks, validate Beyla trace support before you deploy to production.
  The same applies to OpenTelemetry SDKs.
  SDK coverage varies by language and framework, and if no SDK instrumentation exists for your framework, the SDK collects no data.
- Don't run Beyla tracing and SDK tracing in parallel for the same service unless you have verified the behavior.
  To control how Beyla handles services that already export OpenTelemetry data, refer to [Exclude instrumented services][exclude-otel].

## Next steps

- [Beyla requirements and limitations][requirements]
- [Set up Beyla][setup]
- [Language quickstart guides][quickstart]

[exclude-otel]: ../../configure/service-discovery/#exclude-otel-instrumented-services
[requirements]: ../requirements/
[setup]: ../../setup/
[quickstart]: ../../quickstart/
