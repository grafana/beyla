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

The Beyla Helm chart deploys Grafana Beyla as a DaemonSet, so one Beyla Pod runs on each node and instruments the applications on that node.
To configure the chart for Grafana Cloud Application Observability and Knowledge Graph, refer to [Deploy Beyla in Kubernetes with Helm for Grafana Cloud][helm-cloud].

## Before you begin

Before you install the chart, make sure you have the following:

- A Kubernetes cluster whose nodes meet the [Beyla requirements and limitations][requirements]
- Helm and `kubectl`, configured for the cluster
- Permission to create cluster-scoped resources and privileged Pods
- The Prometheus Operator, if you want the chart to create a ServiceMonitor

## Install the chart

Add the Grafana Helm repository and update your local chart index:

```sh
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
```

The following command deploys a Beyla DaemonSet with a default configuration in the `beyla` namespace:

```sh
helm upgrade --install beyla grafana/beyla --namespace beyla --create-namespace
```

Check that a Beyla Pod runs on each node:

```sh
kubectl get pods --namespace beyla
```

With the default values, the chart configures Beyla to do the following:

- Exports metrics in Prometheus format on port `9090` of each Pod, at the `/metrics` path
- Instruments applications in every namespace, except Kubernetes system namespaces and other namespaces that Beyla [excludes by default][default-exclude]
- Collects application-level metrics, not [network-level metrics][network]
- Decorates the metrics with Kubernetes metadata labels, for example `k8s_namespace_name` or `k8s_pod_name`

To collect network metrics instead of application metrics, set `preset: network`.

By default, the chart runs Beyla as a privileged container in the host PID namespace.
To run Beyla with a list of Linux capabilities instead, set `privileged: false`.
For the capabilities, refer to [Beyla security, permissions, and capabilities][security].

The chart also sets `contextPropagation.enabled: true` by default.
This value grants the Pod the access that [network-level context propagation][context-propagation] needs: the host network namespace, the host `/sys/fs/cgroup` and `/sys/kernel/tracing` directories, and, when `privileged: false`, the `NET_ADMIN` capability.
It doesn't turn on context propagation in Beyla.
To turn it on, set `ebpf.context_propagation` under `config.data`.

If you don't use network-level context propagation, set `contextPropagation.enabled: false` to remove this access.
The `network` preset still runs Beyla in the host network namespace.

## Customize the Beyla configuration

To change what Beyla instruments or where it sends data, override the chart values.
The `config.data` value holds the Beyla configuration file that the chart renders into a ConfigMap.
For the configuration options, refer to [Configure Beyla][configure].

Helm merges the values you supply with the chart defaults.
It merges maps key by key and replaces lists.
To remove a chart default, set it to `null`.

The chart keeps exporting Prometheus metrics after you add an OpenTelemetry exporter, unless you set `prometheus_export: null` under `config.data`.

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

The chart also has values for resource names, Pod labels and annotations, the service account, RBAC rules, security contexts, scheduling, and resource limits.
For the full list, refer to the [Beyla Helm chart README][chart-readme].

## Pass OTLP credentials from a Kubernetes Secret

To send metrics and traces to an OTLP endpoint that requires authentication, such as Grafana Cloud, pass the authentication header in the `OTEL_EXPORTER_OTLP_HEADERS` environment variable.
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
  For Grafana Cloud, generate them from the **OpenTelemetry** tile of your stack, as described in [Send data to the Grafana Cloud OTLP endpoint][cloud-otlp].
- _`<OTLP_ENDPOINT>`_: The base URL of your OTLP endpoint.

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
