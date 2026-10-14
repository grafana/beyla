# Beyla Runbook

This document is a collection of runbooks for Beyla. For generic troubleshooting, refer to the [troubleshooting guide](troubleshooting.md).

## Alerts

### BeylaOTELMetricExportHighErrorRate

This alert is triggered when the error rate of the OpenTelemetry metric exporter is high.

#### Impact

- Partial loss of metrics
- Reduced observability

#### Troubleshooting

1. Check the logs of the OpenTelemetry collector and verify that the configuration is correct. Verify the network connection between Beyla and the OpenTelemetry collector.
2. Verify Beyla Metrics configuration and check Beyla logs.


### BeylaOTELTraceExportHighErrorRate

This alert is triggered when the error rate of the OpenTelemetry trace exporter is high.

#### Impact

- Partial loss of traces
- Degraded distributed tracing

#### Troubleshooting

1. Check the logs of the OpenTelemetry collector and verify that the configuration is correct. Verify the network connection between Beyla and the OpenTelemetry collector.
2. Verify Beyla Trace configuration and check Beyla logs. Check sampling and batch settings in Beyla configuration.

### BeylaInstrumentedProcessesNoTelemetry

This alert is triggered when no telemetry data is received from instrumented processes. Note: this alert is only triggered if you have internal metrics enabled.

#### Impact

- Reduced observability

#### Troubleshooting

1. Check Beyla logs for any errors. Enable `BEYLA_LOG_LEVEL=debug` to get more detailed logs. If there are no logs, try enabling `BEYLA_BPF_DEBUG=1` to get more detailed BPF logs.
2. Check that Beyla has the correct permissions to access the BPF subsystem. Verify that the Beyla kernel module is loaded and running.
3. Verify that you have a recent version of Beyla to avoid known issues.