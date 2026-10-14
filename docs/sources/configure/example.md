---
title: Beyla configuration YAML example
menuTitle: YAML example
description: Example Beyla configuration YAML example.
weight: 100
keywords:
  - Beyla
  - eBPF
---

## YAML file example

An example Beyla YAML configuration file to send OTLP data to Grafana Cloud OTLP endpoint:

```yaml
discovery:
  instrument:
    - open_ports: 443
log_level: DEBUG

ebpf:
  wakeup_len: 100

otel_traces_export:
  endpoint: https://otlp-gateway-prod-eu-west-0.grafana.net/otlp

prometheus_export:
  port: 8999
  path: /metrics
```
