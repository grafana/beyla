---
title: Deploy Beyla in Kubernetes with Helm
menuTitle: Helm chart for other use cases
description: Learn how to deploy Beyla as a Helm chart in Kubernetes.
weight: 300
keywords:
  - Beyla
  - eBPF
  - Kubernetes
  - Helm
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/setup/kubernetes-helm/
---

# Deploy Beyla in Kubernetes with Helm

{{% admonition type="note" %}}
For more details about the diverse Helm configuration options, check out the
[Beyla Helm chart options](https://github.com/grafana/beyla/blob/main/charts/beyla/README.md)
document.
{{% /admonition %}}

Contents:

<!-- TOC -->

- [Deploy Beyla with helm](#deploy-beyla-from-helm)
- [Configure Beyla](#configure-beyla)
- [Configure Beyla metadata](#configure-beyla-metadata)
- [Provide secrets to the Helm configuration](#provide-secrets-to-the-helm-configuration)
<!-- TOC -->

## Deploy Beyla with helm

First, you need to add the Grafana helm repository to Helm:

```sh
helm repo add grafana https://grafana.github.io/helm-charts
```

The following command deploys a Beyla DaemonSet with a default configuration in the `beyla` namespace:

```sh
helm upgrade --install beyla grafana/beyla --namespace beyla --create-namespace
```

With the default values, the chart configures Beyla to do the following:

- exports the metrics as Prometheus metrics in the Pod HTTP port `9090`, `/metrics` path.
- instruments applications in every namespace, except Kubernetes system namespaces and other namespaces that Beyla [excludes by default](../../configure/service-discovery/#default-exclude-services-from-instrumentation).
- only provides application-level metrics and excludes [network-level metrics](../../network/) by default
- decorates the metrics with Kubernetes metadata labels, for example `k8s_namespace_name` or `k8s_pod_name`

## Configure Beyla

You might want to override the default configuration of Beyla. For example, to export metrics and traces
with OpenTelemetry, or to restrict the number of services to instrument.

You can override the default [Beyla configuration options](../../configure/) with your own values.

Helm merges the values you supply with the chart defaults.
It merges maps key by key and replaces lists.
To remove a chart default, set it to `null`.
For example, the chart keeps exporting Prometheus metrics after you add an OpenTelemetry exporter, unless you set `prometheus_export: null` under `config.data`.

For example, create a `helm-beyla.yml` file with a custom configuration:

```yaml
config:
  data:
    # Contents of the actual Beyla configuration file
    discovery:
      instrument:
        - k8s_namespace: demo
        - k8s_namespace: blog
    routes:
      unmatched: heuristic
```

The `config.data` section contains a Beyla configuration file, documented in [Configure Beyla](../../configure/).

Apply the file to a new or existing release:

```sh
helm upgrade --install beyla grafana/beyla --namespace beyla --create-namespace -f helm-beyla.yml
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
