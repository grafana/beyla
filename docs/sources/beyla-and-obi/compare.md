---
title: Compare Beyla and OpenTelemetry eBPF Instrumentation
menuTitle: Compare Beyla and OBI
description: Compare Grafana Beyla with OpenTelemetry eBPF Instrumentation (OBI), including how the projects relate, how their configuration differs, and what Beyla adds for the Grafana ecosystem.
weight: 100
keywords:
  - Beyla
  - eBPF
  - OpenTelemetry eBPF Instrumentation
aliases:
  - ../obi/ # /docs/beyla/<BEYLA_VERSION>/obi/
  - ../introduction/obi/ # /docs/beyla/<BEYLA_VERSION>/introduction/obi/
---

# Compare Beyla and OpenTelemetry eBPF Instrumentation

[OpenTelemetry eBPF Instrumentation][obi-docs] (OBI) is the open source, vendor-neutral eBPF auto-instrumentation project in OpenTelemetry.
Grafana Beyla is the Grafana Labs distribution of OBI.

Grafana Labs [donated the Beyla code to the OpenTelemetry project][donation-blog] in 2025 as OBI.
A community of contributors, including Grafana Labs, maintains OBI.

OBI works with the Grafana Cloud OTLP endpoint, and with any OpenTelemetry Collector or Prometheus-compatible backend.

[obi-docs]: https://opentelemetry.io/docs/zero-code/obi/
[donation-blog]: https://grafana.com/blog/opentelemetry-ebpf-instrumentation-beyla-donation/

## How Beyla and OBI relate

The [OBI code repository][obi-repo] contains the eBPF auto-instrumentation code, and the [Grafana Beyla code repository][beyla-repo] imports it as a library.
Every feature that's available in OBI is also available in Beyla.
Both projects are open source, and both export data in the OpenTelemetry format and as Prometheus metrics.

Beyla adds features on top of OBI that make it easier to adopt eBPF-based auto-instrumentation in the Grafana ecosystem.
For details, refer to [What Beyla adds][beyla-adds].

For metrics and attributes that don't follow an OpenTelemetry semantic convention because none exists yet, Beyla prefixes the names with `beyla_` while OBI prefixes them with `obi_`.
For example, Beyla reports the network-level flow bytes metric as `beyla_network_flow_bytes_total`, and OBI reports it as `obi_network_flow_bytes_total`.

[obi-repo]: https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation
[beyla-repo]: https://github.com/grafana/beyla

### Configuration

Beyla and OBI share the Config v1 YAML schema, which the Beyla documentation uses.
Most Beyla configuration examples also work with OBI Config v1, except for the features in [What Beyla adds][beyla-adds].

OBI also has Config v2, which uses the OpenTelemetry declarative configuration structure.
The OBI documentation recommends Config v2 for new configurations, and OBI Config v1 receives no bug fixes or new features.
For details, refer to [Configure OBI][obi-configure].

Beyla also accepts an OBI Config v2 file.
Config v2 doesn't include Beyla-only settings, such as the `grafana` section and survey mode, so use Config v1 for those features.

With Config v1, the environment variable prefixes differ.
OBI uses the `OTEL_EBPF_` prefix, and Beyla uses the `BEYLA_` prefix.
The rest of each environment variable name is the same in both projects.

For example, to set the logging verbosity level, OBI accepts the `OTEL_EBPF_LOG_LEVEL` environment variable, and Beyla accepts `BEYLA_LOG_LEVEL`.

OBI and Beyla both support the [OpenTelemetry common environment variables][otel-env-vars], for example `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_EXPORTER_OTLP_PROTOCOL`.

Config v2 doesn't map the `OTEL_EBPF_` and `BEYLA_` environment variables to its fields.
To set a Config v2 field from an environment variable, use a `${VAR}` expression in the file.

[obi-configure]: https://opentelemetry.io/docs/zero-code/obi/configure/
[otel-env-vars]: https://opentelemetry.io/docs/languages/sdk-configuration/otlp-exporter/
[beyla-adds]: #what-beyla-adds

## What Beyla adds

Beyla includes the following features for the Grafana ecosystem:

- **Grafana Cloud configuration**: Sends data to the Grafana Cloud OTLP endpoint with the [`grafana.otlp`][grafana-otlp] configuration section or the `GRAFANA_CLOUD_*` environment variables.
- **Process metrics**: Reports CPU, memory, disk, and network metrics for the processes that Beyla instruments.
- **Survey mode**: Discovers your services and detects their programming languages, without instrumenting them.
- **Grafana Alloy integration**: Runs as an Alloy component that you can manage with Fleet Management.
- **Grafana AI Observability support**: Adds the span attributes that AI Observability uses.
- **Tempo inter-cluster service graph support**: In Kubernetes, sends connector spans for connections to and from addresses outside the cluster, so Tempo can build service graph connections between clusters. To turn it on, add `inter_cluster` to `topology.spans`.

If you use OBI, you can get most of these capabilities with other OpenTelemetry projects, though not always completely.
For example, the OpenTelemetry Collector reports most of the Beyla process metrics, but not `process.network.io`.
To set this up, and to configure OBI for Grafana Cloud, refer to [Use OpenTelemetry eBPF Instrumentation with Grafana][use-obi].

[use-obi]: ../use-obi/
[grafana-otlp]: ../../configure/export-data/#grafana-cloud-otlp-endpoint

## Choose Beyla or OBI

Both projects provide the eBPF auto-instrumentation benefits that [Why use Grafana Beyla][why-beyla] describes, because they share the same instrumentation code.

The two projects have different release cycles.
Beyla usually releases more often than OBI, so some features are available in Beyla before they're in an OBI release.

Choose Beyla if you want the features in [What Beyla adds][beyla-adds] built in.
Choose OBI if you want to use the OpenTelemetry project release directly, and add the capabilities you need with other OpenTelemetry projects.

[why-beyla]: ../../introduction/why-beyla/

## Next steps

- [Use OpenTelemetry eBPF Instrumentation with Grafana][use-obi]
- [Beyla requirements and limitations][requirements]
- [Set up Beyla][setup]

[requirements]: ../../requirements-and-security/requirements/
[setup]: ../../setup/

