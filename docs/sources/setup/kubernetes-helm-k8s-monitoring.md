---
title: Deploy Beyla with the Kubernetes Monitoring Helm chart
menuTitle: Kubernetes Monitoring Helm chart
description: Deploy Grafana Beyla as the auto-instrumentation feature of the Grafana Kubernetes Monitoring Helm chart, which runs Beyla alongside cluster monitoring and uses Grafana Alloy to collect Beyla metrics and traces and send them to Grafana Cloud.
weight: 500
keywords:
  - Beyla
  - eBPF
  - Kubernetes
  - Helm
  - Grafana Cloud
  - Application Observability
  - Knowledge Graph
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/setup/kubernetes-helm-k8s-monitoring/
---

# Deploy Beyla with the Kubernetes Monitoring Helm chart

The [Kubernetes Monitoring Helm chart][k8s-monitoring-helm] deploys Beyla through its `autoInstrumentation` feature, alongside cluster monitoring, for Grafana Cloud [Knowledge Graph][knowledge-graph] and [Application Observability][app-o11y].
The chart deploys Beyla as a DaemonSet, together with a Beyla Kubernetes metadata cache.
Grafana Alloy, which the chart also deploys, scrapes the Prometheus metrics from Beyla and sends them to your metrics destinations.
If you enable the chart's `applicationObservability` feature with an OTLP receiver, Beyla also sends traces to Alloy over OTLP by default, and Alloy sends them to your traces destinations.

To deploy Beyla on its own and send data directly to Grafana Cloud, refer to [Deploy Beyla with the Beyla Helm chart for Grafana Cloud][appolly].

## Before you begin

Before you deploy Beyla, make sure you have the following:

- A Kubernetes cluster whose nodes meet the [Beyla requirements and limitations][requirements]
- Helm and `kubectl`, configured for the cluster
- Permission to create cluster-scoped resources and privileged Pods
- A Grafana Cloud stack with Kubernetes Monitoring activated.
  To activate it, follow the procedure in [Activate and send data from your account][k8s-monitoring-activate].

With the default chart values, Beyla runs as a privileged DaemonSet in the host process ID (PID) and network namespaces of each node.

## Deploy Beyla with Kubernetes Monitoring

To deploy Beyla, enable the `autoInstrumentation` feature in your Kubernetes Monitoring Helm chart values, then upgrade the chart:

1. If you haven't installed the Kubernetes Monitoring Helm chart, install it.
   Follow the procedure in [Configuration steps for Kubernetes Monitoring with Helm chart][k8s-monitoring-wizard] or [Configure Kubernetes Monitoring with a manual values file][k8s-monitoring-manual].

1. If you don't have a `values.yaml` file for the chart, save the current values:

   ```sh
   helm get values grafana-k8s-monitoring --namespace <NAMESPACE> --output yaml > values.yaml
   ```

   Replace _`<NAMESPACE>`_ with the namespace you installed the chart in.
   The commands on this page use the release name `grafana-k8s-monitoring` from the Grafana Cloud documentation.
   If you used a different release name, use that name instead.
   The file can contain your Grafana Cloud access token, so store it securely.

1. Add the following to your `values.yaml` file:

   ```yaml
   autoInstrumentation:
     enabled: true
   ```

1. Upgrade the chart with your values file:

   ```sh
   helm upgrade --install grafana-k8s-monitoring grafana/k8s-monitoring --namespace <NAMESPACE> --values values.yaml
   ```

1. Check that the Beyla and Beyla Kubernetes metadata cache Pods are running:

   ```sh
   kubectl get pods --namespace <NAMESPACE> --selector 'app.kubernetes.io/name in (beyla,beyla-k8s-cache)'
   ```

   If a Pod isn't running, check its logs with `kubectl logs --namespace <NAMESPACE> <POD_NAME>`, where _`<POD_NAME>`_ is the Pod name from the previous command.

With this configuration, Beyla does the following:

- Exposes Prometheus metrics, including span and service graph metrics, which the chart's Alloy instance scrapes and sends to your metrics destinations
- Sends traces to Alloy, if you enable `applicationObservability` with an OTLP receiver
- Instruments applications in every namespace, except Alloy, OpenTelemetry Collector, and Beyla processes, Kubernetes system namespaces, and other namespaces that Beyla [excludes by default][default-exclude]

To receive traces, set `applicationObservability.enabled` to `true` and enable an OTLP receiver, for example `applicationObservability.receivers.otlp.grpc.enabled`.
To turn traces off, set `autoInstrumentation.beyla.deliverTracesToApplicationObservability` to `false`.

## Customize the Beyla configuration

To change which namespaces Beyla instruments, which Beyla version runs, or other Beyla options, add values under `autoInstrumentation.beyla` in your `values.yaml` file.
Then run the `helm upgrade --install` command again.

For example:

```yaml
autoInstrumentation:
  enabled: true
  beyla:
    image:
      tag: <BEYLA_VERSION>
    config:
      data:
        discovery:
          instrument:
            - k8s_namespace: alpha
            - k8s_namespace: bravo
            - k8s_namespace: delta
```

Replace _`<BEYLA_VERSION>`_ with a Beyla release version.
If you omit `image.tag`, the chart uses the Beyla version that it pins.

The example configures Beyla to do the following:

- Instrument only three namespaces: `alpha`, `bravo`, and `delta`
- Use the Beyla _`<BEYLA_VERSION>`_ image instead of the version that the chart pins

Your `instrument` list replaces the chart's default selection of every namespace.
Unless you set `exclude_instrument`, the chart still excludes Alloy, Collector, and Beyla processes.
Beyla also applies its [default exclusions][default-exclude].

### Settings the chart manages

The `autoInstrumentation.beyla.config.data` section contains a Beyla configuration file.
For the available options, refer to [Configure Beyla][configure].

The chart sets the following keys, so values you set for them in `config.data` have no effect:

- `attributes.kubernetes.enable`, always `true`
- `attributes.kubernetes.cluster_name`, from `cluster.name`
- `internal_metrics.prometheus.port` and `prometheus_export.port`, from `autoInstrumentation.beyla.service.targetPort`

To change the exported metric features, set `prometheus_export.features`.
The chart sets `prometheus_export.features`, and Beyla gives that list precedence over `metrics.features`, so a `metrics.features` list has no effect.

## Next steps

- [Configure Beyla][configure]
- [Configure Beyla service discovery][service-discovery]
- [Configure Kubernetes Monitoring with Helm chart][k8s-monitoring-config]

[app-o11y]: https://grafana.com/docs/grafana-cloud/monitor-applications/application-observability/
[appolly]: ../kubernetes-helm-appolly/
[configure]: ../../configure/
[default-exclude]: ../../configure/service-discovery/#default-exclude-services-from-instrumentation
[k8s-monitoring-activate]: https://grafana.com/docs/grafana-cloud/monitor-infrastructure/kubernetes-monitoring/configuration/activate/
[k8s-monitoring-config]: https://grafana.com/docs/grafana-cloud/monitor-infrastructure/kubernetes-monitoring/configuration/config-k8s-helmchart/
[k8s-monitoring-helm]: https://github.com/grafana/k8s-monitoring-helm/
[k8s-monitoring-manual]: https://grafana.com/docs/grafana-cloud/monitor-infrastructure/kubernetes-monitoring/configuration/helm-chart-config/hc-manual-config/
[k8s-monitoring-wizard]: https://grafana.com/docs/grafana-cloud/monitor-infrastructure/kubernetes-monitoring/configuration/helm-chart-config/hc-config-steps/
[knowledge-graph]: https://grafana.com/docs/grafana-cloud/knowledge-graph/
[requirements]: ../../introduction/requirements/
[service-discovery]: ../../configure/service-discovery/
