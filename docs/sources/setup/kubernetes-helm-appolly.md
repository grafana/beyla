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

With the default chart values, Beyla runs as a privileged DaemonSet in the host process ID (PID) and network namespaces of each node.

## Deploy Beyla for Grafana Cloud

To deploy Beyla for Grafana Cloud, complete the following steps:

1. If the `beyla` namespace doesn't exist, create it with `kubectl create namespace beyla`.

1. Save the following Secret as `grafana-secret.yml`, and create it with `kubectl apply -f grafana-secret.yml`:

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

   Replace _`<BASE64_CREDENTIALS>`_ with your instance ID and token, joined by a colon and Base64-encoded.
   For example, run `echo -n '<INSTANCE_ID>:<TOKEN>' | base64`.

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

   Replace _`<OTLP_ENDPOINT>`_ with the OTLP endpoint that you copied from your stack, for example `https://otlp-gateway-prod-eu-west-0.grafana.net/otlp`.
   Beyla appends `/v1/metrics` and `/v1/traces`.

1. Add the Grafana Helm repository and update your local chart index:

   ```sh
   helm repo add grafana https://grafana.github.io/helm-charts
   helm repo update
   ```

1. Install the chart:

   ```sh
   helm upgrade --install beyla grafana/beyla --namespace beyla -f helm-beyla.yml
   ```

1. Check that the Beyla Pods are running:

   ```sh
   kubectl get pods --namespace beyla
   ```

   If a Pod isn't running, check its logs with `kubectl logs --namespace beyla <POD_NAME>`, where _`<POD_NAME>`_ is the Pod name from the previous command.

After your applications receive requests, their services appear in [Application Observability][app-o11y] in your Grafana Cloud stack.

With this configuration, Beyla does the following:

- Instruments applications in every namespace, except Kubernetes system namespaces and other namespaces that Beyla [excludes by default][default-exclude]
- Exports span metrics, service graph metrics, and traces to Grafana Cloud
- Exports the `application_host` metric, which Grafana Cloud uses for host-based pricing
- Adds Kubernetes metadata attributes, for example `k8s.namespace.name` and `k8s.pod.name`
- Doesn't export [network-level metrics][network] or Prometheus metrics

The `features` list replaces the default Beyla `application` feature, so Beyla exports span metrics instead of OpenTelemetry semantic-convention RED metrics.

## Customize the deployment

To change the chart defaults, add chart values or Beyla options to your `helm-beyla.yml` file and run the `helm upgrade --install` command again.
Keep the `metrics.features` list and the OTLP settings in the file.

- To review each chart default and what it grants, refer to [Review the chart defaults][helm-defaults].
- To instrument only some namespaces or change other Beyla options, refer to [Customize the Beyla configuration][helm-customize].
- To run Beyla with fewer privileges, refer to [Reduce Beyla privileges][helm-reduce].

## Next steps

- [Application Observability][app-o11y]
- [Configure Beyla][configure]
- [Beyla Helm chart README][chart-readme]

[app-o11y]: https://grafana.com/docs/grafana-cloud/monitor-applications/application-observability/
[beyla-helm]: ../kubernetes-helm/
[chart-readme]: https://github.com/grafana/beyla/blob/main/charts/beyla/README.md
[cloud-otlp]: https://grafana.com/docs/grafana-cloud/send-data/otlp/send-data-otlp/#manual-opentelemetry-setup-for-advanced-users
[configure]: ../../configure/
[default-exclude]: ../../configure/service-discovery/#default-exclude-services-from-instrumentation
[helm-customize]: ../kubernetes-helm/#customize-the-beyla-configuration
[helm-defaults]: ../kubernetes-helm/#review-the-chart-defaults
[helm-reduce]: ../kubernetes-helm/#reduce-beyla-privileges
[knowledge-graph]: https://grafana.com/docs/grafana-cloud/knowledge-graph/
[network]: ../../network/
[requirements]: ../../introduction/requirements/
[sample-traces]: ../../configure/sample-traces/
