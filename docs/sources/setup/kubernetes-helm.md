---
title: Deploy Beyla with the Beyla Helm chart
menuTitle: Beyla Helm chart
description: Install Grafana Beyla in Kubernetes with the Beyla Helm chart, customize its configuration, scrape its metrics with the Prometheus Operator, and pass OTLP credentials from a Secret.
weight: 300
keywords:
  - Beyla
  - eBPF
  - Kubernetes
  - Helm
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/setup/kubernetes-helm/
---

# Deploy Beyla with the Beyla Helm chart

The Beyla Helm chart deploys Grafana Beyla as a DaemonSet, which runs a Beyla Pod on each node and instruments the applications on that node.
To configure the chart for Grafana Cloud Application Observability and Knowledge Graph, refer to [Deploy Beyla in Kubernetes with Helm for Grafana Cloud][helm-cloud].

## Before you begin

Before you install the chart, make sure you have the following:

- A Kubernetes cluster whose nodes meet the [Beyla requirements and limitations][requirements]
- Helm and `kubectl`, configured for the cluster
- Permission to create cluster-scoped resources and privileged Pods
- The Prometheus Operator, if you want the chart to create a ServiceMonitor

## Review the chart defaults

With the default values, the chart configures Beyla to do the following:

- Exports metrics in Prometheus format on port `9090` of each node, at the `/metrics` path
- Instruments applications in every namespace, except Kubernetes system namespaces and other namespaces that Beyla [excludes by default][default-exclude]
- Collects application-level metrics, not [network-level metrics][network]
- Decorates the metrics with Kubernetes metadata labels, for example `k8s_namespace_name` or `k8s_pod_name`

To collect network metrics instead of application metrics, set the chart value `preset: network`.

The DaemonSet doesn't tolerate any node taints by default, so tainted nodes, such as control-plane nodes, don't run a Beyla Pod.
To run Beyla on tainted nodes, set the chart value `tolerations`.

By default, the chart runs Beyla as a privileged container in the host process ID (PID) namespace.
The chart also sets `contextPropagation.enabled: true`, which grants the Pod the access that [network-level context propagation][context-propagation] needs:

- The host network namespace
- The host `/sys/fs/cgroup` and `/sys/kernel/tracing` directories
- The `NET_ADMIN` capability, when `privileged: false`

This value doesn't turn on context propagation in Beyla.
To turn it on, set `ebpf.context_propagation` to `all`, `headers`, or `tcp` under `config.data`.

With host networking, Beyla listens on port `9090` of the node.
If another process on the node uses that port, set `config.data.prometheus_export.port` to a free port.

To change these defaults, refer to [Customize the Beyla configuration](#customize-the-beyla-configuration) and [Reduce Beyla privileges](#reduce-beyla-privileges).

## Install the chart

To install the chart with its default values, complete the following steps:

1. Add the Grafana Helm repository and update your local chart index:

   ```sh
   helm repo add grafana https://grafana.github.io/helm-charts
   helm repo update
   ```

1. Install the chart in the `beyla` namespace:

   ```sh
   helm upgrade --install beyla grafana/beyla --namespace beyla --create-namespace
   ```

1. Check that the Beyla Pods are running:

   ```sh
   kubectl get pods --namespace beyla
   ```

## Customize the Beyla configuration

To change what Beyla instruments or where it sends data, override the chart values in a values file.
Your values file has two kinds of settings:

- Top-level chart values, such as `privileged` and `preset`, control the Kubernetes resources that the chart creates
- Values under `config.data` form the Beyla configuration file, which the chart renders into a ConfigMap

For the Beyla configuration options, refer to [Configure Beyla][configure].
The chart also has values for resource names, Pod labels and annotations, the service account, RBAC rules, security contexts, scheduling, and resource limits.
For the full list, refer to the [Beyla Helm chart README][chart-readme].

Helm merges the values you supply with the chart defaults.
It merges maps key by key and replaces lists.
To remove a chart default, set it to `null`.

For example, create a `helm-beyla.yml` file that instruments only the `demo` and `blog` namespaces and uses the `heuristic` [routes decorator][routes]:

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

If you set any `discovery` option, the chart doesn't add its default `instrument` selector.
Include an `instrument` selector, or Beyla exits at startup with a `missing application discovery section` error.

Install or upgrade the release with the file:

```sh
helm upgrade --install beyla grafana/beyla --namespace beyla --create-namespace -f helm-beyla.yml
```

## Reduce Beyla privileges

To run Beyla with a list of Linux capabilities instead of a privileged container, set the chart value `privileged: false` in your `helm-beyla.yml` file.
For the capabilities, refer to [Beyla security, permissions, and capabilities][security].
The chart still runs Beyla in the host PID namespace.

If you don't use network-level context propagation, set the chart value `contextPropagation.enabled: false` to remove the access that it needs.
The `network` preset still runs Beyla in the host network namespace.

Apply the updated `helm-beyla.yml` file with the same `helm upgrade --install` command.

## Scrape metrics with the Prometheus Operator

If you run the Prometheus Operator, the chart can create a Service and a ServiceMonitor so Prometheus discovers the Beyla metrics endpoint.
The chart creates the ServiceMonitor only when `config.data.prometheus_export` has a value, as it does by default.
Add the following to your `helm-beyla.yml` file:

```yaml
service:
  enabled: true

serviceMonitor:
  enabled: true
  endpoint:
    honorLabels: true
```

The `honorLabels` setting keeps the `instance` and `job` labels that Beyla sets for each instrumented process.
For more information, refer to [Prometheus exporter component][prometheus-exporter].

Apply the updated `helm-beyla.yml` file with the same `helm upgrade --install` command.

## Pass OTLP credentials from a Kubernetes Secret

Some OTLP endpoints, such as Grafana Cloud, require an authentication header.
Pass it to Beyla in the `OTEL_EXPORTER_OTLP_HEADERS` environment variable.
Store the header in a Kubernetes Secret, and reference the Secret from your Helm values.

Create a Secret in the namespace where Beyla runs:

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

Add the endpoint to `env`, and reference the Secret from `envValueFrom` in your `helm-beyla.yml` file:

```yaml
env:
  OTEL_EXPORTER_OTLP_ENDPOINT: "<OTLP_ENDPOINT>"
envValueFrom:
  OTEL_EXPORTER_OTLP_HEADERS:
    secretKeyRef:
      key: otlp-headers
      name: grafana-secret
```

Replace the following:

- _`<BASE64_CREDENTIALS>`_: The Base64-encoded credentials for your OTLP endpoint.
  For Grafana Cloud, generate them from the **OpenTelemetry** tile of your stack.
  For the steps, refer to [Send data to the Grafana Cloud OTLP endpoint][cloud-otlp].
- _`<OTLP_ENDPOINT>`_: The base URL of your OTLP endpoint.

Beyla still exports Prometheus metrics after you add the OTLP endpoint.
To export only through OTLP, set `prometheus_export: null` under `config.data`.

Apply the updated `helm-beyla.yml` file with the same `helm upgrade --install` command.

## Next steps

- [Beyla Helm chart README][chart-readme]
- [Configure Beyla][configure]
- [Deploy Beyla in Kubernetes with Helm for Grafana Cloud][helm-cloud]

[chart-readme]: https://github.com/grafana/beyla/blob/main/charts/beyla/README.md
[cloud-otlp]: https://grafana.com/docs/grafana-cloud/send-data/otlp/send-data-otlp/#manual-opentelemetry-setup-for-advanced-users
[configure]: ../../configure/
[context-propagation]: ../../traces/#context-propagation-at-network-level
[default-exclude]: ../../configure/service-discovery/#default-exclude-services-from-instrumentation
[helm-cloud]: ../kubernetes-helm-appolly/
[network]: ../../network/
[prometheus-exporter]: ../../configure/export-data/#prometheus-exporter-component
[requirements]: ../../introduction/requirements/
[routes]: ../../configure/routes-decorator/
[security]: ../security/
