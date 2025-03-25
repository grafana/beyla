{
  prometheusAlerts+: {
    groups+: [
      {
        name: 'beyla_internal_alerts',
        rules: [
          {
            alert: 'BeylaOTELMetricExportHighErrorRate',
            expr: |||
              100 * sum(rate(beyla_otel_metric_export_errors_total[1m])) by (cluster)
                /
              sum(rate(beyla_otel_metric_exports_total[1m])) by (cluster)
                > 2
            |||,
            'for': '15m',
            labels: {
              severity: 'warning',
            },
            annotations: {
              summary: 'Beyla has a high error rate for OTEL metric exports',
              description: 'Beyla in { $labels.cluster }} is experiencing {{ printf "%.2f" $value }}% errors for OTEL metric exports.',
              runbook_url: 'https://github.com/grafana/beyla/tree/main/ops/runbook.md#BeylaOTELMetricExportHighErrorRate',
            },
          },
          {
            alert: 'BeylaOTELMetricExportHighErrorRate',
            expr: |||
              100 * sum(rate(beyla_otel_metric_export_errors_total[1m])) by (cluster)
                /
              sum(rate(beyla_otel_metric_exports_total[1m])) by (cluster)
                > 5
            |||,
            'for': '15m',
            labels: {
              severity: 'critical',
            },
            annotations: {
              summary: 'Beyla has a high error rate for OTEL metric exports',
              description: 'Beyla in { $labels.cluster }} is experiencing {{ printf "%.2f" $value }}% errors for OTEL metric exports.',
              runbook_url: 'https://github.com/grafana/beyla/tree/main/ops/runbook.md#BeylaOTELMetricExportHighErrorRate',
            },
          },
          {
            alert: 'BeylaOTELTraceExportHighErrorRate',
            expr: |||
              100 * sum(rate(beyla_otel_trace_export_errors_total[1m])) by (cluster)
                /
              sum(rate(beyla_otel_trace_exports_total[1m])) by (cluster)
                > 2
            |||,
            'for': '15m',
            labels: {
              severity: 'warning',
            },
            annotations: {
              summary: 'Beyla has a high error rate for OTEL trace exports',
              description: 'Beyla in { $labels.cluster }} is experiencing {{ printf "%.2f" $value }}% errors for OTEL trace exports.',
              runbook_url: 'https://github.com/grafana/beyla/tree/main/ops/runbook.md#BeylaOTELTraceExportHighErrorRate',
            },
          },
          {
            alert: 'BeylaOTELTraceExportHighErrorRate',
            expr: |||
              100 * sum(rate(beyla_otel_trace_export_errors_total[1m])) by (cluster)
                /
              sum(rate(beyla_otel_trace_exports_total[1m])) by (cluster)
                > 5
            |||,
            'for': '15m',
            labels: {
              severity: 'critical',
            },
            annotations: {
              summary: 'Beyla has a high error rate for OTEL trace exports',
              description: 'Beyla in { $labels.cluster }} is experiencing {{ printf "%.2f" $value }}% errors for OTEL trace exports.',
              runbook_url: 'https://github.com/grafana/beyla/tree/main/ops/runbook.md#BeylaOTELTraceExportHighErrorRate',
            },
          },                   
          {
            alert: 'BeylaInstrumentedProcessesNoTelemetry',
            expr: |||
              sum by(cluster) (beyla_instrumented_processes{process_name!="beyla"}) > 1 and 
              (absent(sum by(cluster) (rate(beyla_otel_metric_exports_total[5m]))) or
               absent(sum by(cluster) (rate(beyla_otel_trace_exports_total[5m]))) or 
               absent(sum by(cluster) (rate(beyla_ebpf_tracer_flushes_sum[5m]))) or 
               absent(sum by(cluster) (rate(beyla_prometheus_http_requests_total[5m]))))
            |||,
            'for': '10m',
            labels: {
              severity: 'warning',
            },
            annotations: {
              summary: 'Beyla has instrumented processes without metrics or traces',
              description: 'Beyla in { $labels.cluster }} has are more than 1 instrumented processes, but no metrics or traces have been exported in the last 10 minutes.',
              runbook_url: 'https://github.com/grafana/beyla/tree/main/ops/runbook.md#BeylaInstrumentedProcessesNoTelemetry',
            },
          },              
        ],
      },
    ],
  },
}
