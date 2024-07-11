---
title: Set up Beyla network metrics in Kubernetes with Helm for Asserts
menuTitle: Set up Asserts network
description: A guide to install Beyla network metrics in Kubernetes with Helm for Asserts.
weight: 1
keywords:
  - Beyla
  - eBPF
  - Network
---

# Set up Beyla network metrics in Kubernetes with Helm for Asserts

[Asserts](/docs/grafana-cloud/monitor-applications/asserts/) works with Beyla and requires Beyla network metrics. Learn how to set up Beyla network metrics in Kubernetes with Helm to export telemetry data to Asserts.

To learn more about Beyla network metrics, consult the [Network](/docs/beyla/latest/network/) documentation.

## Prerequisites

Before you install Beyla network metrics and export telemetry data to Asserts you need:

1. A free Grafana Cloud account.
1. An application to auto-instrument with Beyla.
1. A Linux environment that supports eBPF kernel modules.
1. Administrative `sudo` privileges or `CAP_SYS_ADMIN` permissions.

You can register for a [free forever Grafana Cloud account](https://grafana.com/auth/sign-up/create-user?) in minutes and start sending telemetry data and monitoring your infrastructure and applications.

## Install Beyla with Helm

Create a Helm `values.yml` for Beyla with the following content:

```yaml
preset: network

# If using kubernetes-monitoring helm chart and scraping metrics
podAnnotations:
  k8s.grafana.com/scrape: true
  k8s.grafana.com/job: beyla-network
  k8s.grafana.com/metrics.portName: metrics

# else if using an otel-collector for metrics collection
env:
  OTEL_EXPORTER_OTLP_ENDPOINT: your-otlp-endpoint:4318
```
Run the following `helm` commands to add the `grafana` repo and install `beyla`:

```sh
helm repo add grafana https://grafana.github.io/helm-charts
helm install beyla --create-namespace -n beyla -f values.yaml grafana/beyla
```

/todo, what do people have to do next?
