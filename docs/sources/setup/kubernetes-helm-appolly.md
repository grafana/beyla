---
title: Deploy Beyla with the Beyla Helm chart for Grafana Cloud
menuTitle: Beyla Helm chart for Grafana Cloud
description: Deploy Grafana Beyla with the Beyla Helm chart and send span metrics, service graph metrics, and traces directly to the Grafana Cloud OTLP endpoint for Application Observability and Knowledge Graph, with no collector in between.
weight: 400
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

# Deploy Beyla with the Beyla Helm chart for Grafana Cloud

Grafana Cloud [Application Observability][app-o11y] and [Knowledge Graph][knowledge-graph] use span metrics and service graph metrics.
Other instrumentation usually derives these metrics from traces.
Beyla generates them directly, so you can [sample traces][sample-traces] or turn traces off and still get complete request rate, error, and duration (RED) metrics.

With the [Beyla Helm chart][beyla-helm], Beyla sends these metrics and traces directly to the Grafana Cloud OTLP endpoint, with no collector in between.

## Before you begin

Before you deploy Beyla, make sure you have the following:

- A Kubernetes cluster whose nodes meet the [Beyla requirements and limitations][requirements]
- Helm and `kubectl`, configured for the cluster
- Permission to create cluster-scoped resources and privileged Pods
- A Grafana Cloud stack, and the OTLP endpoint and credentials for it.
  To find them, follow the procedure in [Send data to the Grafana Cloud OTLP endpoint][cloud-otlp].

## Deploy Beyla for Grafana Cloud

To deploy Beyla for Grafana Cloud, complete the following steps:

1. Create the `beyla` namespace with `kubectl create namespace beyla`.

1. Create a Secret with your Grafana Cloud credentials:

   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: grafana-secret
     namespace: beyla
   type: Opaque
   stringData:
     otlp-headers: "Authorization=Basic <BASE64_CREDENTIALS>"
   ```

1. Create a `helm-beyla.yml` file:

   ```yaml
   config:
     data:
       metrics:
         features:
           - application_span
           - application_service_graph
           - application_host
       prometheus_export: null
   env:
     OTEL_EXPORTER_OTLP_ENDPOINT: "<OTLP_ENDPOINT>"
   envValueFrom:
     OTEL_EXPORTER_OTLP_HEADERS:
       secretKeyRef:
         key: otlp-headers
         name: grafana-secret
   ```

1. Add the Grafana Helm repository, as described in [Install the chart][helm-install], and install the chart:

   ```sh
   helm upgrade --install beyla grafana/beyla --namespace beyla --create-namespace -f helm-beyla.yml
   ```

Replace the following:

- _`<BASE64_CREDENTIALS>`_: The Base64-encoded instance ID and token for your stack.
  For the steps, refer to [Send data to the Grafana Cloud OTLP endpoint][cloud-otlp].
- _`<OTLP_ENDPOINT>`_: The OTLP endpoint of your stack, for example `https://otlp-gateway-<ZONE>.grafana.net/otlp`.
  Beyla appends `/v1/metrics` and `/v1/traces`.

With this configuration, Beyla does the following:

- Instruments applications in every namespace, except Kubernetes system namespaces and other namespaces that Beyla [excludes by default][default-exclude]
- Exports span metrics, service graph metrics, and traces to Grafana Cloud
- Exports the `application_host` metric, which Grafana Cloud uses for host-based pricing
- Adds Kubernetes metadata attributes, for example `k8s.namespace.name` and `k8s.pod.name`
- Doesn't export [network-level metrics][network] or Prometheus metrics

The `features` list replaces Beyla's default `application` feature, so Beyla exports span metrics instead of OpenTelemetry semantic-convention RED metrics.

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

[app-o11y]: https://grafana.com/docs/grafana-cloud/monitor-applications/application-observability/
[beyla-helm]: ../kubernetes-helm/
[cloud-otlp]: https://grafana.com/docs/grafana-cloud/send-data/otlp/send-data-otlp/#manual-opentelemetry-setup-for-advanced-users
[default-exclude]: ../../configure/service-discovery/#default-exclude-services-from-instrumentation
[helm-install]: ../kubernetes-helm/#install-the-chart
[knowledge-graph]: https://grafana.com/docs/grafana-cloud/knowledge-graph/
[network]: ../../network/
[requirements]: ../../introduction/requirements/
[sample-traces]: ../../configure/sample-traces/
