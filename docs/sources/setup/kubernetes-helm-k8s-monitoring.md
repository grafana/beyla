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

The [Kubernetes Monitoring Helm chart][k8s-monitoring-helm] deploys Beyla as its auto-instrumentation feature, alongside cluster monitoring, for Grafana Cloud [Knowledge Graph][knowledge-graph] and [Application Observability][app-o11y].
The chart deploys Beyla as a DaemonSet, together with a Beyla Kubernetes metadata cache.
Grafana Alloy, which the chart also deploys, scrapes the Prometheus metrics from Beyla and sends them to your metrics destinations.
If you enable the chart's Application Observability feature with an OTLP receiver, Beyla also sends traces to Alloy over OTLP.

To deploy Beyla on its own and send data directly to Grafana Cloud, refer to [Deploy Beyla with the Beyla Helm chart for Grafana Cloud][appolly].

## Before you begin

Before you deploy Beyla, make sure you have the following:

- A Kubernetes cluster whose nodes meet the [Beyla requirements and limitations][requirements]
- Helm and `kubectl`, configured for the cluster
- Permission to create cluster-scoped resources and privileged Pods
- A Grafana Cloud stack with Kubernetes Monitoring

With the default chart values, Beyla runs as a privileged DaemonSet in the host process ID (PID) and network namespaces of each node.

## Deploy Beyla with Kubernetes Monitoring

To enable Beyla, open the Kubernetes Monitoring configuration page in your Grafana Cloud stack, for example:

```text
https://<STACK_SLUG>.grafana.net/a/grafana-k8s-app/configuration?from=now-1h&to=now
```

Replace _`<STACK_SLUG>`_ with the subdomain of your Grafana Cloud stack.

In the **Containerized application monitoring** section, enable **Auto Instrumentation** > **Metrics of inbound and outbound calls**.
To also generate OpenTelemetry traces from Beyla, enable **Forward traces to application receivers**.

After you choose your other options, the Kubernetes Monitoring UI generates a Helm deployment script with the settings you need.
The script contains the Beyla settings in the `autoInstrumentation` section.

The following example shows a generated script with the `autoInstrumentation` section:

```sh
helm repo add grafana https://grafana.github.io/helm-charts &&
  helm repo update &&
  helm upgrade --install --atomic --timeout 300s grafana-k8s-monitoring grafana/k8s-monitoring \
    --namespace "default" --create-namespace --values - <<'EOF'
cluster:
  name: my-cluster
destinations:
# ...
autoInstrumentation:
  enabled: true
  beyla:
    deliverTracesToApplicationObservability: false
# ...
EOF
```

With this configuration, Beyla does the following:

- Exposes Prometheus metrics, including span and service graph metrics, which the chart's Alloy instance scrapes and sends to your metrics destinations
- Doesn't send traces, because `deliverTracesToApplicationObservability` is `false`
- Instruments applications in every namespace, except Kubernetes system namespaces and other namespaces that Beyla [excludes by default][default-exclude]

To check that Beyla is running, list the Beyla Pods:

```sh
kubectl get pods --namespace <NAMESPACE> --selector app.kubernetes.io/name=beyla
```

Replace _`<NAMESPACE>`_ with the namespace you installed the chart in, for example `default`.
If a Pod isn't running, check its logs with `kubectl logs --namespace <NAMESPACE> <POD_NAME>`, where _`<POD_NAME>`_ is the Pod name from the previous command.

## Customize the Beyla configuration

You can override the default [Beyla configuration options][configure] with your own values, for example to choose which namespaces Beyla instruments or to run a different Beyla version.

To override the defaults, modify the `autoInstrumentation` section of the generated script and run the script again, for example:

```sh
helm repo add grafana https://grafana.github.io/helm-charts &&
  helm repo update &&
  helm upgrade --install --atomic --timeout 300s grafana-k8s-monitoring grafana/k8s-monitoring \
    --namespace "default" --create-namespace --values - <<'EOF'
cluster:
  name: my-cluster
destinations:
# ...
autoInstrumentation:
  enabled: true
  beyla:
    deliverTracesToApplicationObservability: true
    image:
      tag: <BEYLA_VERSION>
    config:
      data:
        discovery:
          instrument:
            - k8s_namespace: alpha
            - k8s_namespace: bravo
            - k8s_namespace: delta
# ...
EOF
```

Replace _`<BEYLA_VERSION>`_ with a Beyla release version, for example `3.25.0`.
If you omit `image.tag`, the chart uses the Beyla version that it pins.

The `autoInstrumentation.beyla.config.data` section contains a Beyla configuration file.
For the available options, refer to [Configure Beyla][configure].

The chart sets `attributes.kubernetes.enable`, sets `attributes.kubernetes.cluster_name` from `cluster.name`, and sets `internal_metrics.prometheus.port` and `prometheus_export.port` from `autoInstrumentation.beyla.service.targetPort`.
Values you set for these keys in `config.data` have no effect.

To change the exported metric features, set `prometheus_export.features`.
The chart sets `prometheus_export.features`, and Beyla gives that list precedence over `metrics.features`, so a `metrics.features` list has no effect.

The example configures Beyla to do the following:

- Send traces to the Application Observability feature's OTLP receiver, if you enable `applicationObservability` with an OTLP receiver
- Instrument only three namespaces: `alpha`, `bravo`, and `delta`
- Use the Beyla _`<BEYLA_VERSION>`_ image instead of the version that the chart pins

Your `instrument` list replaces the chart's default selection of every namespace.
Unless you set `exclude_instrument`, the chart still excludes Alloy, OpenTelemetry Collector, and Beyla processes.
Beyla also applies its [default exclusions][default-exclude].

## Next steps

- [Configure Beyla][configure]
- [Configure Beyla service discovery][service-discovery]
- [Kubernetes Monitoring Helm chart][k8s-monitoring-helm]

[app-o11y]: https://grafana.com/docs/grafana-cloud/monitor-applications/application-observability/
[appolly]: ../kubernetes-helm-appolly/
[configure]: ../../configure/
[default-exclude]: ../../configure/service-discovery/#default-exclude-services-from-instrumentation
[k8s-monitoring-helm]: https://github.com/grafana/k8s-monitoring-helm/
[knowledge-graph]: https://grafana.com/docs/grafana-cloud/knowledge-graph/
[requirements]: ../../introduction/requirements/
[service-discovery]: ../../configure/service-discovery/
