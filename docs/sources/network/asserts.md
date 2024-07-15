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
1. Access rights to a Kubernetes cluster, enough to create components with privileges.

You can register for a [free forever Grafana Cloud account](/auth/sign-up/create-user) in minutes and start sending telemetry data and monitoring your infrastructure and applications.

There are two configuration options to collect metrics to send to Grafana Cloud for Asserts. First, through Kubernetes monitoring or alternatively with an OpenTelemetry Collector.

## Configuration for Kubernetes monitoring

If you use Kubernetes monitoring and a Helm chart for scraping metrics, create a `values.yml` with the following configuration:

```yaml
preset: network

podAnnotations:
  k8s.grafana.com/scrape: true
  k8s.grafana.com/job: beyla-network
  k8s.grafana.com/metrics.portName: metrics
```

## Configure for OpenTelemetry Collector

If you use an OpenTelemetry Collector for metrics collection, either Grafana Alloy the upstream collector, create a `values.yml` with the following configuration:

```sh
preset: network

env:
  OTEL_EXPORTER_OTLP_ENDPOINT: your-otlp-endpoint:4318
```

## Install and run Beyla network metrics for Asserts

Run the following `helm` commands to add the `grafana` repository and install and run `beyla` with your configuration for network metrics:

```sh
helm repo add grafana https://grafana.github.io/helm-charts
helm install beyla --create-namespace -n beyla -f values.yaml grafana/beyla
```

## Observe your services in Asserts

Finally, navigate to Asserts in [Grafana Cloud](/auth/sign-in/) and view your instrumented services.
