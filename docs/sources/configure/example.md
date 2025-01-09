## YAML file example

```yaml
open_port: 443
service_name: my-instrumented-service
log_level: DEBUG

ebpf:
  wakeup_len: 100

otel_traces_export:
  endpoint: https://otlp-gateway-prod-eu-west-0.grafana.net/otlp

prometheus_export:
  port: 8999
  path: /metrics
```
