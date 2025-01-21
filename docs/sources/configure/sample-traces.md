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

Beyla accepts the standard OpenTelemetry environment variables to configure the
sampling ratio of traces.

In addition, you can configure the sampling under the `sampler` YAML subsection of the
`otel_traces_export` section. For example:

```yaml
otel_traces_export:
  sampler:
    name: "traceidratio"
    arg: "0.1"
```

If you are using the Grafana Alloy as your OTEL collector, you can configure the sampling
policy at that level instead.

| YAML   | Environment variable  | Type   | Default                 |
| ------ | --------------------- | ------ | ----------------------- |
| `name` | `OTEL_TRACES_SAMPLER` | string | `parentbased_always_on` |

Specifies the name of the sampler. It accepts the following standard sampler
names from the [OpenTelemetry specification](https://opentelemetry.io/docs/concepts/sdk-configuration/general-sdk-configuration/#otel_traces_sampler):

- `always_on`: samples every trace. Be careful about using this sampler in an
  application with significant traffic: a new trace will be started and exported
  for every request.
- `always_off`: samples no traces.
- `traceidratio`: samples a given fraction of traces (specified by the `arg` property
  that is explained below). The fraction must be a real value between 0 and 1.
  For example, a value of `"0.5"` would sample 50% of the traces.
  Fractions >= 1 will always sample. Fractions < 0 are treated as zero. To respect the
  parent trace's sampling configuration, the `parentbased_traceidratio` sampler should be used.
- `parentbased_always_on` (default): parent-based version of `always_on` sampler (see
  explanation below).
- `parentbased_always_off`: parent-based version of `always_off` sampler (see
  explanation below).
- `parentbased_traceidratio`: parent-based version of `traceidratio` sampler (see
  explanation below).

Parent-based samplers are composite samplers which behave differently based on the
parent of the traced span. If the span has no parent, the root sampler is used to
make sampling decision. If the span has a parent, the sampling configuration
would depend on the sampling parent.

| YAML  | Environment variable      | Type   | Default |
| ----- | ------------------------- | ------ | ------- |
| `arg` | `OTEL_TRACES_SAMPLER_ARG` | string | (unset) |

Specifies the argument of the selected sampler. Currently, only `traceidratio`
and `parentbased_traceidratio` require an argument.

In YAML, this value MUST be provided as a string, so even if the value
is numeric, make sure that it is enclosed between quotes in the YAML file,
(for example, `arg: "0.25"`).

