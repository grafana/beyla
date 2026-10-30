---
title: Deploy Beyla with the Beyla Helm chart
menuTitle: Beyla Helm chart
description: Install Grafana Beyla in Kubernetes with the Beyla Helm chart, customize its configuration, reduce its privileges, scrape its metrics with the Prometheus Operator, and pass OTLP credentials from a Secret.
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

The Beyla Helm chart deploys Grafana Beyla as a DaemonSet, which runs a Beyla Pod on your cluster nodes and instruments the applications on each node.
To configure the chart for Grafana Cloud Application Observability and Knowledge Graph, refer to [Deploy Beyla in Kubernetes with Helm for Grafana Cloud][helm-cloud].

## Before you begin

Before you install the chart, make sure you have the following:

- A Kubernetes cluster whose nodes meet the [Beyla requirements and limitations][requirements]
- Helm and `kubectl`, configured for the cluster
- Permission to create cluster-scoped resources and privileged Pods
- The Prometheus Operator, if you want the chart to create a ServiceMonitor

## Review the chart defaults

With the default values, Beyla does the following:

- Instruments applications in every namespace, except Kubernetes system namespaces and other namespaces that Beyla [excludes by default][default-exclude]
- Collects application-level metrics, not [network-level metrics][network]
- Adds Kubernetes metadata labels to metrics, for example `k8s_namespace_name` and `k8s_pod_name`
- Exports metrics in Prometheus format on port `9090` of each node, at the `/metrics` path

The following chart values control what Beyla collects, where it runs, and what access its Pods get on each node:

| Chart value                  | Default       | Effect                                                                                                                                   |
| ---------------------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `preset`                     | `application` | Instruments all namespaces and runs Beyla in the host process ID (PID) namespace. Set `network` to collect network metrics instead.      |
| `privileged`                 | `true`        | Runs Beyla as a privileged container.                                                                                                    |
| `contextPropagation.enabled` | `true`        | Gives the Pod host network access, the host `/sys/fs/cgroup` and `/sys/kernel/tracing` directories, and, when unprivileged, `NET_ADMIN`. |
| `tolerations`                | `[]`          | Skips nodes with taints that the DaemonSet doesn't tolerate, such as control-plane nodes.                                                |

The `contextPropagation.enabled` value grants the access that [network-level context propagation][context-propagation] needs, but doesn't turn it on in Beyla.

If another process on the node uses port `9090`, change `config.data.prometheus_export.port`.

To change these defaults, refer to [Customize the Beyla configuration][customize] and [Reduce Beyla privileges][reduce].

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

- Top-level chart values, such as `privileged` and `tolerations`, control the Kubernetes resources that the chart creates
- Values under `config.data` form the Beyla configuration file, which the chart renders into a ConfigMap

The `preset` chart value changes both the Kubernetes resources and the Beyla configuration.

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

To reduce the access that Beyla gets on each node, add one or both of the following chart values to your `helm-beyla.yml` file:

```yaml
privileged: false
contextPropagation:
  enabled: false
```

The `privileged: false` value runs Beyla with a list of Linux capabilities instead of a privileged container.
For the capabilities, refer to [Beyla security, permissions, and capabilities][security].
The chart still runs Beyla in the host PID namespace.

The `contextPropagation.enabled: false` value removes the access that network-level context propagation needs.
If you set `ebpf.context_propagation` under `config.data`, keep `contextPropagation.enabled: true`.
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

If your Prometheus selects ServiceMonitors by label, add that label with the chart value `serviceMonitor.additionalLabels`.

Apply the updated `helm-beyla.yml` file with the same `helm upgrade --install` command.

## Pass OTLP credentials from a Kubernetes Secret

Some OTLP endpoints, such as Grafana Cloud, require an authentication header.
Pass it to Beyla in the `OTEL_EXPORTER_OTLP_HEADERS` environment variable.
Store the header in a Kubernetes Secret, and reference the Secret from your Helm values.
The `OTEL_EXPORTER_OTLP_ENDPOINT` variable sends both metrics and traces to the endpoint.

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

## Use your own ConfigMap

To manage the Beyla configuration file outside the chart, store it in a ConfigMap in the Beyla namespace.
If you haven't installed the chart yet, create the namespace first with `kubectl create namespace beyla`.
Use the `beyla-config.yml` key, because Beyla reads its configuration from `/etc/beyla/config/beyla-config.yml`:

```sh
kubectl create configmap beyla-config --namespace beyla --from-file=beyla-config.yml=<CONFIG_FILE>
```

Replace _`<CONFIG_FILE>`_ with the path to your Beyla configuration file.

Then set the chart value `config.name` to the ConfigMap name in your `helm-beyla.yml` file:

```yaml
config:
  name: beyla-config
```

With `config.name` set, the chart doesn't create its own ConfigMap or render `config.data` into one.
The chart still reads `config.data.prometheus_export` to set the container port, the Service, and the ServiceMonitor.
Keep that value consistent with the `prometheus_export` section of your file.
The `preset` value doesn't add its defaults to your file, so include a `discovery` or `network` section.

The chart doesn't restart the Beyla Pods when your ConfigMap changes.
To restart them on the next upgrade, set the chart value `config.checksum` to a value that changes with your ConfigMap.

## Next steps

- [Beyla Helm chart README][chart-readme]
- [Configure Beyla][configure]
- [Deploy Beyla in Kubernetes with Helm for Grafana Cloud][helm-cloud]

[chart-readme]: https://github.com/grafana/beyla/blob/main/charts/beyla/README.md
[cloud-otlp]: https://grafana.com/docs/grafana-cloud/send-data/otlp/send-data-otlp/#manual-opentelemetry-setup-for-advanced-users
[configure]: ../../configure/
[context-propagation]: ../../traces/#context-propagation-at-network-level
[customize]: #customize-the-beyla-configuration
[default-exclude]: ../../configure/service-discovery/#default-exclude-services-from-instrumentation
[helm-cloud]: ../kubernetes-helm-appolly/
[network]: ../../network/
[prometheus-exporter]: ../../configure/export-data/#prometheus-exporter-component
[reduce]: #reduce-beyla-privileges
[requirements]: ../../introduction/requirements/
[routes]: ../../configure/routes-decorator/
[security]: ../security/
