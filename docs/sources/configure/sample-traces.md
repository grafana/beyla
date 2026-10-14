---
title: Configure Beyla OpenTelemetry trace sampling
menuTitle: Sample traces
description: Configure how to sample OpenTelemetry traces.
weight: 70
keywords:
  - Beyla
  - eBPF
---

# Configure Beyla OpenTelemetry trace sampling

Beyla accepts the standard OpenTelemetry environment variables to configure the sampling ratio of traces.

YAML section: `otel_traces_export.sampler`

You can configure the component under the `otel_traces_export.sampler` section of your YAML configuration or via environment variables.

```yaml
otel_traces_export:
  sampler:
    name: "traceidratio"
    arg: "0.1"
```

If you're using Grafana Alloy as your OTEL collector, you can configure the sampling policy at that level instead.

| YAML<p>environment variable</p>       | Description                                                                                                                                                                                                                                                            | Type   | Default                 |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | ----------------------- |
| `name`<p>`OTEL_TRACES_SAMPLER`</p>    | Specifies the name of the sampler. Accepts standard sampler names from the [OpenTelemetry specification](https://opentelemetry.io/docs/concepts/sdk-configuration/general-sdk-configuration/#otel_traces_sampler). Refer to [sampler name](#sampler-name) for details. | string | `parentbased_always_on` |
| `arg`<p>`OTEL_TRACES_SAMPLER_ARG`</p> | Specifies the argument for the selected sampler. Only `traceidratio` and `parentbased_traceidratio` require an argument. Refer to [sampler argument](#sampler-argument) for details.                                                                                   | string | (unset)                 |

## Sampler name

The `name` property accepts the following standard sampler names:

- `always_on`: samples every trace. Be careful using this sampler in an application with significant traffic: a new trace will be started and exported for every request
- `always_off`: samples no traces
- `traceidratio`: samples a given fraction of traces (specified by the `arg` property). The fraction must be a real value between 0 and 1. For example, a value of `"0.5"` samples 50% of the traces. Fractions >= 1 always sample. Fractions < 0 are treated as zero. To respect the parent trace's sampling configuration, use the `parentbased_traceidratio` sampler
- `parentbased_always_on` (default): parent-based version of `always_on` sampler
- `parentbased_always_off`: parent-based version of `always_off` sampler
- `parentbased_traceidratio`: parent-based version of `traceidratio` sampler

Parent-based samplers are composite samplers that behave differently based on the parent of the traced span. If the span has no parent, the root sampler is used to make the sampling decision. If the span has a parent, the sampling configuration depends on the sampling parent.

## Sampler argument

The `arg` property specifies the argument for the selected sampler. Only `traceidratio` and `parentbased_traceidratio` require an argument.

In YAML, you MUST provide this value as a string. Even if the value is numeric, make sure to enclose it in quotes in the YAML file (for example, `arg: "0.25"`).
