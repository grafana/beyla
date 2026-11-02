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

Grafana Alloy is a vendor-neutral distribution of the OpenTelemetry Collector.
Alloy offers native pipelines for OpenTelemetry, Prometheus, and other telemetry signals.

Grafana Alloy bundles Beyla allowing you to instrument your applications at the same time
you instrument your infrastructure. It also provides a Helm chart to deploy Alloy in Kubernetes.

The Alloy [`beyla.ebpf` component](https://grafana.com/docs/alloy/latest/reference/components/beyla/beyla.ebpf/) runs Beyla as a child process inside the Alloy container.
Alloy scrapes the Beyla metrics through the `targets` export of the component, and receives the Beyla traces through the `output` block of the component.
You can then process and route the Beyla telemetry with other Alloy components.

You configure Beyla with the `beyla.ebpf` block in [Alloy syntax](https://grafana.com/docs/alloy/latest/get-started/syntax/), not with the Beyla YAML configuration file.
Each Alloy release includes a specific Beyla version, which the `beyla.ebpf` component reference lists.

Use this option if you run Alloy in your cluster, or want to process the Beyla telemetry in Alloy pipelines.
To deploy Beyla on its own, refer to [Deploy Beyla with the Beyla Helm chart](../kubernetes-helm/).
To deploy Beyla with Kubernetes cluster monitoring, refer to [Deploy Beyla with the Kubernetes Monitoring Helm chart](../kubernetes-helm-k8s-monitoring/).

## Before you begin

Before you deploy Beyla, make sure you have the following:

- A Kubernetes cluster, you can use [kind](https://kind.sigs.k8s.io/) to create a local cluster
- `kubectl` installed and configured for your cluster
- [Helm](https://helm.sh/) installed
- A Grafana Cloud stack, or a Prometheus remote write endpoint and an OTLP endpoint for traces

## Prepare the Alloy environment

Add the Grafana Helm chart repository, update it, and create the `alloy` namespace:

```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
kubectl create namespace alloy
```

You install the Alloy Helm chart in this namespace after you create the credentials and the Alloy configuration.

## Configure credentials

In this setup, Alloy sends the Beyla metrics to the Grafana Cloud Prometheus remote write endpoint and the traces to the Grafana Cloud Tempo OTLP endpoint. You can get a [free Grafana Cloud Account](/pricing/).

Find the URL, user, and password for each endpoint:

- Prometheus: In the [Cloud Portal](https://grafana.com/docs/grafana-cloud/platform/security-and-account-management/account-management/cloud-portal/), click **Details** in the **Prometheus** card. The password is a Cloud Access Policy token. For more information, refer to [Send metrics data from Prometheus](https://grafana.com/docs/grafana-cloud/send-data/metrics/metrics-prometheus/).
- Tempo: Follow the procedure in [Locate your stack's URL, user, and password](https://grafana.com/docs/grafana-cloud/send-data/traces/set-up/locate-url-user-password/).

Create a `secrets.yml` file with your Grafana Cloud credentials for the Prometheus and Tempo endpoints. Deploy it with the command `kubectl apply -f secrets.yml`.

```yaml
apiVersion: v1
kind: Secret
metadata:
  namespace: alloy
  name: grafana-credentials
type: Opaque
stringData:
  prometheus-rw-user: "prom-user"
  prometheus-rw-pwd: "prom-pwd"
  tempo-rw-user: "tempo-user"
  tempo-rw-pwd: "tempo-pwd"
```

## Create the Alloy configuration

Create a `ConfigMap` with the Alloy configuration. Copy the following contents into a file, for example `config.alloy`:

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

Deploy the configuration with the command:

```bash
kubectl create configmap --namespace alloy alloy-config "--from-file=config.alloy=./config.alloy"
```

With this configuration Beyla instruments the applications in the _`<NAMESPACE>`_ namespace, and Alloy sends the traces to Grafana Cloud Tempo and the metrics to Grafana Cloud Prometheus.

The `attributes > kubernetes > enable` enables Kubernetes decoration for metrics and traces, which adds the metadata of the Kubernetes entities running the automatically instrumented services.

The `discovery > instrument > kubernetes` block selects the services to instrument by their Kubernetes metadata, with glob patterns. In this example, Beyla instruments the applications in the _`<NAMESPACE>`_ namespace.

The `prometheus.scrape` section configures Prometheus scrape to collect metrics from Beyla. The `honor_labels = true` setting preserves the per-process instance identifiers set by Beyla. The `prometheus.remote_write` section sends the metrics to Grafana Cloud Prometheus.

The `output` section configures that Beyla component sends traces to `otelcol.exporter.otlp` component. The `otelcol.exporter.otlp` section configures the [OTLP exporter](/docs/alloy/latest/reference/components/otelcol.exporter.otlp) to send the traces to Grafana Cloud Tempo.

For further details on the configuration options, refer to the documentation of the [Grafana Alloy Beyla component](/docs/alloy/latest/reference/components/beyla.ebpf)

## Install the Alloy Helm chart

Create a `values.yaml` with the configuration for the Alloy Helm chart. Copy the following contents into a file, for example `values.yaml`.

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

- To run in DaemonSet mode, Beyla requires to have access to all the
  processes in the node. Therefore set `hostPID: true` the `controller` section.
- The Alloy container runs Beyla as a child process, and Beyla loads eBPF programs, so the Alloy container needs elevated privileges.
  The `privileged: true` value in the `alloy.securityContext` section grants all capabilities.
  For production, the Alloy documentation recommends that you run Alloy without `privileged: true` and grant only the capabilities that Beyla needs, as described in [Kubernetes: unprivileged, root user](https://grafana.com/docs/alloy/latest/reference/components/beyla/beyla.ebpf/#kubernetes-unprivileged-root-user).
  For the capabilities and Pod settings, refer to [Permissions](https://grafana.com/docs/alloy/latest/reference/components/beyla/beyla.ebpf/#permissions) in the `beyla.ebpf` component reference.
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
For more information, refer to [Manage data sources in Grafana Cloud](https://grafana.com/docs/grafana-cloud/observe-and-act/connect-externally-hosted/data-sources-in-cloud/).

## Next steps

- [`beyla.ebpf` component reference](https://grafana.com/docs/alloy/latest/reference/components/beyla/beyla.ebpf/)
- [Configure Grafana Alloy on Kubernetes](https://grafana.com/docs/alloy/latest/configure/kubernetes/)
- [Beyla exported metrics](../../metrics/)
