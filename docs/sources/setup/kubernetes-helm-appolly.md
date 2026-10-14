---
title: Deploy Beyla in Kubernetes with Helm for Grafana Cloud
menuTitle: Helm chart for Grafana Cloud
description: Learn how to deploy Beyla with a Helm chart in Kubernetes for Knowledge Graph and Application Observability in Grafana Cloud.
weight: 2
keywords:
  - Beyla
  - eBPF
  - Kubernetes
  - Helm
  - Grafana Cloud
  - Application Observability
  - Knowledge Graph
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/setup/kubernetes-helm-appolly/
---

# Deploy Beyla in Kubernetes with Helm for Grafana Cloud Knowledge Graph and Application Observability

This documentation section explains the best practices for deploying Beyla using the Helm chart, but specifically for
[Grafana Cloud Knowledge Graph](https://grafana.com/docs/grafana-cloud/knowledge-graph/) and [Application Observability](https://grafana.com/docs/grafana-cloud/monitor-applications/application-observability/). 

Knowledge Graph and Application Observability in Grafana Cloud rely on OpenTelemetry span and service graph metrics, 
which are typically produced from traces. Beyla can directly generate span and service graph metrics, without having to generate traces, 
which means that we can configure head sampling for OpenTelemetry traces, or disable trace
generation completely, and still generate correct Request-Error-Duration(RED) metrics. 

If you are familiar with the Grafana Cloud Application Observability configuration for the Tempo span metric generator, this component
is not needed, nor needs to be configured/enabled for Beyla span and service graph metrics generation.

{{< admonition type="note" >}}
For more details about the diverse Helm configuration options, check out the
[Beyla Helm chart options](https://github.com/grafana/beyla/blob/main/charts/beyla/README.md)
document.
{{< /admonition >}}

Contents:

<!-- TOC -->

- [Deploy Beyla with Helm for Grafana Cloud](#deploy-beyla-from-helm)
- [Configure Beyla](#configure-beyla)
- [Configure Beyla metadata](#configure-beyla-metadata)
- [Provide secrets to the Helm configuration](#provide-secrets-to-the-helm-configuration)
<!-- TOC -->

## Deploy Beyla with Helm for Grafana Cloud

First, you need to add the Grafana helm repository to Helm:

```sh
helm repo add grafana https://grafana.github.io/helm-charts
```

If you have previously added the Grafana Helm repository, run the update command to refresh the helm repository information:

```sh
helm repo update
```

The following command deploys a Beyla DaemonSet with a default configuration for Grafana Cloud in the `beyla` namespace:

```sh
helm upgrade --install --atomic --timeout 300s beyla grafana/beyla --namespace "beyla" --create-namespace --values - <<EOF
config:
  data:
    discovery:
      instrument:
        - k8s_namespace: "*"
    otel_metrics_export:
      endpoint: <Your Grafana Cloud tenant Mimir endpoint> e.g. "https://otlp-gateway-ops-eu-south-0.grafana-ops.net/otlp/v1/metrics"
      features:
        - application_span
        - application_service_graph
        - application_host
    otel_traces_export:
      endpoint: <Your Grafana Cloud tenant Tempo endpoint> e.g. "https://otlp-gateway-ops-eu-south-0.grafana-ops.net/otlp/v1/traces"
env:
  OTEL_EXPORTER_OTLP_METRICS_HEADERS: "Authorization=Basic <Your Grafana Cloud Mimir auth token>"
  OTEL_EXPORTER_OTLP_TRACES_HEADERS: "Authorization=Basic <Your Grafana Cloud Tempo auth token>"
EOF
```

The Beyla configuration above:

- exports metrics and traces in a format that can be consumed by Grafana Cloud Knowledge Graph and Application Observability.
- exports host information metrics `application_host` which are needed for the host based pricing model of the Grafana Cloud products.
- tries to instrument all the applications in your cluster.
- only provides application-level metrics (span and service graph) and excludes [network-level metrics](../../network/) by default
- configures Beyla to decorate the metrics with Kubernetes metadata labels, for example `k8s.namespace.name` or `k8s.pod.name`

## Configure Beyla

You might want to override the default configuration of Beyla. For example, to export the metrics using the OpenTelemetry 
semantic conventions instead of span metrics, or to restrict the number of services to instrument.

You can override the default [Beyla configuration options](../../configure/) with your own values.

For example, create a `helm-beyla.yml` file with a custom configuration:

```yaml
config:
  data:
    # Contents of the actual Beyla configuration file,
    # specifying only two Kubernetes namespaces to be instrumented.
    discovery:
      instrument:
        - k8s_namespace: demo
        - k8s_namespace: blog
    metrics:
      features:
        - application_span
        - application_service_graph
        - application_host
    otel_metrics_export:
      endpoint: <Your Grafana Cloud tenant Mimir endpoint> e.g. "https://otlp-gateway-ops-eu-south-0.grafana-ops.net/otlp/v1/metrics"
    otel_traces_export:
      endpoint: <Your Grafana Cloud tenant Tempo endpoint> e.g. "https://otlp-gateway-ops-eu-south-0.grafana-ops.net/otlp/v1/traces"
    routes:
      unmatched: heuristic
env:
  OTEL_EXPORTER_OTLP_METRICS_HEADERS: "Authorization=Basic <Your Grafana Cloud Mimir auth token>"
  OTEL_EXPORTER_OTLP_TRACES_HEADERS: "Authorization=Basic <Your Grafana Cloud Tempo auth token>"
```

The `config.data` section contains a Beyla configuration file, documented in the
[Beyla configuration options documentation](../../configure/options/).

Then pass the overridden configuration to the `helm` command with the `-f` flag. For example:

```sh
helm install beyla grafana/beyla -f helm-beyla.yml
```

or, if the Beyla chart was previously deployed:

```sh
helm upgrade beyla grafana/beyla -f helm-beyla.yml
```

## Configure Beyla metadata

If Beyla exports the data using the Prometheus exporter, you can expose its metrics 
by creating a Kubernetes Service and configuring a ServiceMonitor, allowing your Prometheus scraper to discover it. 
To enable this feature, edit your `helm-beyla.yml` file to include the following configuration:

```yaml
service:
  enabled: true

serviceMonitor:
  enabled: true
```

{{< admonition type="note" >}}
Configure your Prometheus scraper with [`honor_labels: true`](../../configure/export-data/#prometheus-exporter-component) to preserve the per-process instance identifiers set by Beyla.
{{< /admonition >}}

Analogously, the Helm chart allows overriding names, labels, and annotations for
multiple resources involved in the deployment of Beyla, such as service
accounts, cluster roles, security contexts, etc. The
[Beyla Helm chart documentation](https://github.com/grafana/beyla/blob/main/charts/beyla/README.md)
describes the diverse configuration options.

## Provide secrets to the Helm configuration

If you are submitting directly the metrics and traces to Grafana Cloud via the
OpenTelemetry Endpoint, you need to provide the credentials via the
`OTEL_EXPORTER_OTLP_HEADERS` environment variable.

The recommended way is to store such value in a Kubernetes Secret and then
specify the environment variable referring to it from the Helm configuration.

For example, deploy the following secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: grafana-secret
type: Opaque
stringData:
  otlp-headers: "Authorization=Basic ...."
```

Then refer to it from the `helm-config.yml` file via the `envValueFrom` section:

```yaml
env:
  OTEL_EXPORTER_OTLP_ENDPOINT: "<...your Grafana Cloud OTLP endpoint URL...>"
envValueFrom:
  OTEL_EXPORTER_OTLP_HEADERS:
    secretKeyRef:
      key: otlp-headers
      name: grafana-secret
```
