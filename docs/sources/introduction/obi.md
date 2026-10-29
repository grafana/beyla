---
title: Compare Beyla and OpenTelemetry eBPF Instrumentation
menuTitle: Beyla and OBI
description: Compare Grafana Beyla with OpenTelemetry eBPF Instrumentation (OBI), including how the projects relate, how their configuration differs, and which Beyla features OBI doesn't have.
weight: 400
keywords:
  - Beyla
  - eBPF
  - OpenTelemetry eBPF Instrumentation
aliases:
  - ../obi/ # /docs/beyla/<BEYLA_VERSION>/obi/
---

# Compare Beyla and OpenTelemetry eBPF Instrumentation

Grafana Beyla is the Grafana Labs distribution of
[OpenTelemetry eBPF Instrumentation][obi-docs] (OBI).

Grafana Labs [donated the Beyla code to the OpenTelemetry project][donation-blog] in 2025 as OBI.
A community of contributors, including Grafana Labs, maintains OBI.

OBI works with the Grafana Cloud OTLP endpoint, and with any OpenTelemetry or Prometheus collector.

[obi-docs]: https://opentelemetry.io/docs/zero-code/obi/
[donation-blog]: https://grafana.com/blog/opentelemetry-ebpf-instrumentation-beyla-donation/

## Differences between OBI and Beyla

The eBPF auto-instrumentation code lives in the [OBI code repository][obi-repo],
and the [Grafana Beyla code repository][beyla-repo] imports it as a library.
Every feature that's available in OBI is also available in Beyla.

Beyla also has features that OBI doesn't.
Both projects are open source and vendor-neutral, and Beyla adds features that make it easier to adopt eBPF-based auto-instrumentation in the Grafana ecosystem.

The two projects also have different release cycles.
Beyla usually releases more often than OBI, so some features are available in Beyla before they're in an OBI release.

For metrics and attributes that don't follow an OpenTelemetry semantic convention
because none exists yet, Beyla prefixes the names with `beyla_` while
OBI prefixes them with `obi_`.
For example, Beyla reports the network-level flow bytes metric as `beyla_network_flow_bytes_total`, and OBI reports it as `obi_network_flow_bytes_total`.

[obi-repo]: https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation
[beyla-repo]: https://github.com/grafana/beyla

### Configuration

Beyla and OBI use the same YAML configuration schema.
Most Beyla configuration examples also work with OBI, except for the features in [Beyla features that are missing in OBI][missing-features].

The OpenTelemetry documentation also describes
[how to configure OBI from a YAML configuration file][obi-configure].

The environment variable prefixes differ.
OBI uses the `OTEL_EBPF_` prefix, and Beyla uses the `BEYLA_` prefix.
Beyla also accepts the `OTEL_EBPF_` prefix.
The rest of each environment variable name is the same in both projects.

For example, to set the logging verbosity level, OBI accepts the `OTEL_EBPF_LOG_LEVEL` environment
variable, and Beyla accepts both `BEYLA_LOG_LEVEL` and `OTEL_EBPF_LOG_LEVEL`.

OBI and Beyla both support the [OpenTelemetry common environment variables][otel-env-vars],
for example `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_EXPORTER_OTLP_PROTOCOL`.

[obi-configure]: https://opentelemetry.io/docs/zero-code/obi/configure/
[otel-env-vars]: https://opentelemetry.io/docs/languages/sdk-configuration/otlp-exporter/
[missing-features]: #beyla-features-that-are-missing-in-obi

## Beyla features that are missing in OBI

Beyla provides the following features that OBI doesn't:

- **Process metrics**: CPU, memory, disk, and network metrics for the processes that Beyla instruments.
  With OBI, use the OpenTelemetry Collector Host Metrics Receiver.
- **Survey mode**: Discovers your services and detects their programming languages, without instrumenting them.
  OBI doesn't have a replacement.
- **Integration inside Grafana Alloy**: Run Beyla as an Alloy component, and manage it with Fleet Management.
  With OBI, build a custom Collector with OpAMP.
- **Grafana AI Observability support**: With OBI, add the required span attributes in an OpenTelemetry Collector.
- Connecting spans for Tempo service graph metrics

To replace these features when you use OBI, and to configure OBI for Grafana Cloud, refer to [Use OpenTelemetry eBPF Instrumentation with Grafana][use-obi].

[use-obi]: ../../setup/use-obi/

## Next steps

- [Use OpenTelemetry eBPF Instrumentation with Grafana][use-obi]
- [Beyla requirements and limitations][requirements]
- [Set up Beyla][setup]

[requirements]: ../requirements/
[setup]: ../../setup/

