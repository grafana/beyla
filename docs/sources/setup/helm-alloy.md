---
title: Deploy Beyla with the Grafana Alloy Helm chart
menuTitle: Grafana Alloy Helm chart
description: Deploy Grafana Beyla in Kubernetes as the beyla.ebpf component of Grafana Alloy with the Alloy Helm chart, and send Beyla metrics and traces through Alloy pipelines to Grafana Cloud.
weight: 600
keywords:
  - Beyla
  - eBPF
  - Kubernetes
  - Helm
  - Alloy
aliases:
  - /docs/beyla/latest/tutorial/helm-alloy/
---

# Deploy Beyla with the Grafana Alloy Helm chart

Grafana Alloy is a vendor-neutral distribution of the OpenTelemetry Collector, with native pipelines for OpenTelemetry, Prometheus, and other telemetry signals.
Alloy includes Grafana Beyla, so you can instrument your applications with the same Alloy deployment that collects your infrastructure telemetry.
The Alloy Helm chart deploys Alloy in Kubernetes.

The Alloy [`beyla.ebpf` component][alloy-beyla] runs Beyla as a child process inside the Alloy container.
Alloy scrapes the Beyla metrics through the `targets` export of the component, and receives the Beyla traces through the `output` block of the component.
You can then process and route the Beyla telemetry with other Alloy components.

You configure Beyla with the `beyla.ebpf` block in [Alloy syntax][alloy-syntax], not with the Beyla YAML configuration file.
Each Alloy release includes a specific Beyla version, which the `beyla.ebpf` component reference lists.

Use this option if you run Alloy in your cluster, or want to process the Beyla telemetry in Alloy pipelines.
To deploy Beyla on its own, refer to [Deploy Beyla with the Beyla Helm chart][beyla-helm].
To deploy Beyla with Kubernetes cluster monitoring, refer to [Deploy Beyla with the Kubernetes Monitoring Helm chart][k8s-monitoring-helm].

## Before you begin

Before you deploy Beyla, make sure you have the following:

- A Kubernetes cluster whose nodes meet the [Beyla requirements and limitations][requirements].
  For a local cluster, you can use [kind][kind].
- [Helm][helm] and `kubectl`, configured for the cluster
- Permission to create cluster-scoped resources and privileged Pods
- A Grafana Cloud stack, or a Prometheus remote write endpoint and an OTLP endpoint for traces

## Prepare the Alloy environment

Add the Grafana Helm chart repository, update it, and create the `alloy` namespace:

```sh
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
kubectl create namespace alloy
```

You install the Alloy Helm chart in this namespace after you create the credentials and the Alloy configuration.

## Configure credentials

Alloy sends the Beyla metrics to the Grafana Cloud Prometheus remote write endpoint and the traces to the Grafana Cloud Tempo OTLP endpoint. You can get a [free Grafana Cloud account][cloud-pricing].

Find the URL, user, and password for each endpoint:

- **Prometheus**: In the [Cloud Portal][cloud-portal], click **Details** in the **Prometheus** card. The password is a Cloud Access Policy token. For more information, refer to [Send metrics data from Prometheus][cloud-prometheus].
- **Tempo**: Follow the procedure in [Locate your stack's URL, user, and password][cloud-tempo-credentials].

Save the following Secret as `secrets.yml`, and create it with `kubectl apply -f secrets.yml`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  namespace: alloy
  name: grafana-credentials
type: Opaque
stringData:
  prometheus-rw-user: "<PROMETHEUS_USER>"
  prometheus-rw-pwd: "<PROMETHEUS_PASSWORD>"
  tempo-rw-user: "<TEMPO_USER>"
  tempo-rw-pwd: "<TEMPO_PASSWORD>"
```

Replace the placeholders with the user and password for each endpoint.

## Create the Alloy configuration

Save the following Alloy configuration as `config.alloy`:

```alloy
beyla.ebpf "default" {
  attributes {
    kubernetes {
      enable = "true"
    }
  }

  discovery {
    instrument {
      kubernetes {
        namespace = "<NAMESPACE>"
      }
    }
  }

  metrics {
    features = [
      "application",
    ]
  }

  output {
    traces = [otelcol.exporter.otlp.grafana_cloud_tempo.input]
  }
}

prometheus.scrape "beyla" {
  targets      = beyla.ebpf.default.targets
  honor_labels = true
  forward_to   = [prometheus.remote_write.rw.receiver]
}

prometheus.remote_write "rw" {
  endpoint {
    url = "<PROMETHEUS_REMOTE_WRITE_URL>"

    basic_auth {
      username = sys.env("PROMETHEUS_REMOTE_WRITE_USERNAME")
      password = sys.env("PROMETHEUS_REMOTE_WRITE_PASSWORD")
    }
  }
}

otelcol.exporter.otlp "grafana_cloud_tempo" {
  client {
    endpoint = "<TEMPO_ENDPOINT>"
    auth     = otelcol.auth.basic.grafana_cloud_tempo.handler
  }
}

otelcol.auth.basic "grafana_cloud_tempo" {
  username = sys.env("TEMPO_REMOTE_WRITE_USERNAME")
  password = sys.env("TEMPO_REMOTE_WRITE_PASSWORD")
}
```

Replace the following:

- _`<NAMESPACE>`_: The Kubernetes namespace of the applications to instrument
- _`<PROMETHEUS_REMOTE_WRITE_URL>`_: The Prometheus remote write URL of your Grafana Cloud stack, which ends in `/api/prom/push`
- _`<TEMPO_ENDPOINT>`_: The Tempo endpoint of your Grafana Cloud stack, including the `:443` port

Create a ConfigMap from the file:

```sh
kubectl create configmap --namespace alloy alloy-config "--from-file=config.alloy=./config.alloy"
```

With this configuration, Beyla instruments the applications in the _`<NAMESPACE>`_ namespace, and Alloy sends the traces to Grafana Cloud Tempo and the metrics to Grafana Cloud Prometheus.

The `attributes > kubernetes > enable` attribute adds Kubernetes metadata, such as the namespace and Pod name, to the metrics and traces of the instrumented applications.

The `discovery > instrument > kubernetes` block selects the applications to instrument by their Kubernetes metadata, with glob patterns.

The `prometheus.scrape` component collects the Beyla metrics. The `honor_labels = true` setting keeps the per-process `instance` and `job` labels that Beyla sets. The `prometheus.remote_write` component sends the metrics to Grafana Cloud Prometheus.

The `output` block sends the Beyla traces to the `otelcol.exporter.otlp` component. The [OTLP exporter][alloy-otlp-exporter] sends the traces to Grafana Cloud Tempo, and the `otelcol.auth.basic` component authenticates the requests.

For more information about the configuration options, refer to the [Grafana Alloy Beyla component][alloy-beyla] documentation.

## Install the Alloy Helm chart

Save the following Alloy Helm chart values as `values.yaml`:

```yaml
alloy:
  configMap:
    create: false
    name: alloy-config
    key: config.alloy
  securityContext:
    privileged: true
  extraEnv:
    - name: PROMETHEUS_REMOTE_WRITE_USERNAME
      valueFrom:
        secretKeyRef:
          name: grafana-credentials
          key: prometheus-rw-user
    - name: PROMETHEUS_REMOTE_WRITE_PASSWORD
      valueFrom:
        secretKeyRef:
          name: grafana-credentials
          key: prometheus-rw-pwd
    - name: TEMPO_REMOTE_WRITE_USERNAME
      valueFrom:
        secretKeyRef:
          name: grafana-credentials
          key: tempo-rw-user
    - name: TEMPO_REMOTE_WRITE_PASSWORD
      valueFrom:
        secretKeyRef:
          name: grafana-credentials
          key: tempo-rw-pwd

controller:
  type: daemonset
  hostPID: true
```

Install Alloy with the command:

```sh
helm upgrade --install --namespace alloy alloy grafana/alloy -f values.yaml
```

- The `controller.hostPID: true` value runs the Alloy Pods in the host process ID (PID) namespace, so Beyla can find the processes on each node.
- The Alloy container runs Beyla as a child process, and Beyla loads eBPF programs, so the Alloy container needs elevated privileges.
  The `privileged: true` value in the `alloy.securityContext` section grants all capabilities.
  For production, the Alloy documentation recommends that you run Alloy without `privileged: true` and grant only the capabilities that Beyla needs, as described in [Kubernetes: unprivileged, root user][alloy-beyla-unprivileged].
  For the capabilities and Pod settings, refer to [Permissions][alloy-beyla-permissions] in the `beyla.ebpf` component reference.
- The `extraEnv` section sets the environment variables for the Prometheus and Tempo credentials.

## Check that Beyla is running

To check the deployment, complete the following steps:

1. Check that the Alloy Pods are running:

   ```sh
   kubectl get pods --namespace alloy
   ```

1. Check the logs of an Alloy Pod for the `Beyla subprocess started` message:

   ```sh
   kubectl logs --namespace alloy <POD_NAME>
   ```

   Replace _`<POD_NAME>`_ with a Pod name from the previous command.
   Alloy writes the Beyla logs to its own log, with the `source=beyla-subprocess` attribute.

After the applications in the _`<NAMESPACE>`_ namespace receive requests, their traces and metrics appear in your Grafana Cloud stack.
To query the traces, open **Explore** and select the `grafanacloud-<STACK_NAME>-traces` data source, where _`<STACK_NAME>`_ is the name of your Grafana Cloud stack.
For more information, refer to [Manage data sources in Grafana Cloud][cloud-data-sources].

## Next steps

- [`beyla.ebpf` component reference][alloy-beyla]
- [Configure Grafana Alloy on Kubernetes][alloy-kubernetes]
- [Beyla exported metrics][metrics]

[alloy-beyla]: https://grafana.com/docs/alloy/latest/reference/components/beyla/beyla.ebpf/
[alloy-beyla-permissions]: https://grafana.com/docs/alloy/latest/reference/components/beyla/beyla.ebpf/#permissions
[alloy-beyla-unprivileged]: https://grafana.com/docs/alloy/latest/reference/components/beyla/beyla.ebpf/#kubernetes-unprivileged-root-user
[alloy-kubernetes]: https://grafana.com/docs/alloy/latest/configure/kubernetes/
[alloy-otlp-exporter]: https://grafana.com/docs/alloy/latest/reference/components/otelcol/otelcol.exporter.otlp/
[alloy-syntax]: https://grafana.com/docs/alloy/latest/get-started/syntax/
[beyla-helm]: ../kubernetes-helm/
[cloud-data-sources]: https://grafana.com/docs/grafana-cloud/observe-and-act/connect-externally-hosted/data-sources-in-cloud/
[cloud-portal]: https://grafana.com/docs/grafana-cloud/platform/security-and-account-management/account-management/cloud-portal/
[cloud-pricing]: /pricing/
[cloud-prometheus]: https://grafana.com/docs/grafana-cloud/send-data/metrics/metrics-prometheus/
[cloud-tempo-credentials]: https://grafana.com/docs/grafana-cloud/send-data/traces/set-up/locate-url-user-password/
[helm]: https://helm.sh/
[k8s-monitoring-helm]: ../kubernetes-helm-k8s-monitoring/
[kind]: https://kind.sigs.k8s.io/
[metrics]: ../../metrics/
[requirements]: ../../introduction/requirements/
