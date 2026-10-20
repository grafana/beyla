---
title: Run Beyla in Kubernetes with the Grafana Alloy Helm chart
menuTitle: Grafana Alloy Helm chart
description: Learn how to deploy Beyla in Kubernetes with the Grafana Alloy Helm chart and send metrics and traces to Grafana Cloud.
weight: 4
keywords:
  - Beyla
  - eBPF
  - Kubernetes
  - Alloy
  - tutorial
aliases:
  - /docs/beyla/latest/tutorial/helm-alloy/
---

# Run Beyla in Kubernetes with the Grafana Alloy Helm chart

Grafana Alloy is a vendor-neutral distribution of the OpenTelemetry Collector.
Alloy offers native pipelines for OpenTelemetry, Prometheus, and other telemetry signals.

Alloy bundles Beyla, so you can instrument your applications and your infrastructure together.
Alloy also provides a Helm chart to deploy Alloy in Kubernetes.

In this tutorial, you deploy Beyla in Kubernetes with the Grafana Alloy Helm chart and send the metrics and traces to Grafana Cloud.

## Prerequisites

- A Kubernetes cluster, for example a local cluster you create with [kind][kind]
- Linux nodes on `amd64` or `arm64` that meet the [Beyla requirements][requirements]
- `kubectl` installed and configured for your cluster
- [Helm][helm] installed
- A Grafana Cloud account, for example a [free Grafana Cloud account][pricing]

## Prepare the cluster

Add the Grafana Helm repository and create the `alloy` namespace for the Alloy resources:

```sh
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
kubectl create namespace alloy
```

## Deploy the sample services

Beyla instruments HTTP and HTTPS services, among other protocols.
This tutorial uses two sample web servers, `docs` and `website`, in the `default` namespace.

Copy the following contents into a file, for example `sampleapps.yml`:

```yaml
kind: Deployment
apiVersion: apps/v1
metadata:
  name: docs
spec:
  replicas: 2
  selector:
    matchLabels:
      app: docs
  template:
    metadata:
      labels:
        app: docs
    spec:
      containers:
        - name: docs-server
          image: httpd:latest
          ports:
            - containerPort: 80
              protocol: TCP
              name: http
---
apiVersion: v1
kind: Service
metadata:
  name: docs
spec:
  selector:
    app: docs
  ports:
    - protocol: TCP
      port: 80
---
kind: Deployment
apiVersion: apps/v1
metadata:
  name: website
spec:
  replicas: 2
  selector:
    matchLabels:
      app: website
  template:
    metadata:
      labels:
        app: website
    spec:
      containers:
        - name: website-server
          image: httpd:latest
          ports:
            - containerPort: 80
              protocol: TCP
              name: http
---
apiVersion: v1
kind: Service
metadata:
  name: website
spec:
  selector:
    app: website
  ports:
    - protocol: TCP
      port: 80
```

Deploy the services:

```sh
kubectl apply --namespace default -f sampleapps.yml
```

Forward a local port to each service in the background:

```sh
kubectl port-forward --namespace default services/website 8080:80 &
kubectl port-forward --namespace default services/docs 8081:80 &
```

## Create the Grafana Cloud credentials

Alloy can export metrics and traces to any OpenTelemetry endpoint and expose metrics as a Prometheus endpoint.
This tutorial sends metrics to Grafana Cloud Prometheus and traces to Grafana Cloud Traces, powered by Grafana Tempo.

To find your endpoints and credentials, open the Grafana Cloud Portal.
In the **Prometheus** box, click **Send Metrics**.
In the **Tempo** box, click **Send Traces**.
Note the endpoint URLs, because you need them for the Alloy configuration.

Create a `secrets.yml` file with your Grafana Cloud credentials for Prometheus and Tempo:

```yaml
apiVersion: v1
kind: Secret
metadata:
  namespace: alloy
  name: grafana-credentials
type: Opaque
stringData:
  prometheus-rw-user: "<PROMETHEUS_USERNAME>"
  prometheus-rw-pwd: "<PROMETHEUS_PASSWORD>"
  tempo-rw-user: "<TEMPO_USERNAME>"
  tempo-rw-pwd: "<TEMPO_PASSWORD>"
```

Replace the following:

- _`<PROMETHEUS_USERNAME>`_: The user name for your Grafana Cloud Prometheus endpoint.
- _`<PROMETHEUS_PASSWORD>`_: The password for your Grafana Cloud Prometheus endpoint.
- _`<TEMPO_USERNAME>`_: The user name for your Grafana Cloud Tempo endpoint.
- _`<TEMPO_PASSWORD>`_: The password for your Grafana Cloud Tempo endpoint.

Deploy the secret:

```sh
kubectl apply -f secrets.yml
```

## Create the Alloy configuration

Copy the following Alloy configuration into a file, for example `config.alloy`:

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
				namespace       = "default"
				deployment_name = "docs"
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
			username = env("PROMETHEUS_REMOTE_WRITE_USERNAME")
			password = env("PROMETHEUS_REMOTE_WRITE_PASSWORD")
		}
	}
}

otelcol.exporter.otlp "grafana_cloud_tempo" {
	client {
		endpoint = "<TEMPO_OTLP_ENDPOINT>"
		auth     = otelcol.auth.basic.grafana_cloud_tempo.handler
	}
}

otelcol.auth.basic "grafana_cloud_tempo" {
	client_auth {
		username = env("TEMPO_REMOTE_WRITE_USERNAME")
		password = env("TEMPO_REMOTE_WRITE_PASSWORD")
	}
}
```

Replace the following:

- _`<PROMETHEUS_REMOTE_WRITE_URL>`_: The remote write URL of your Grafana Cloud Prometheus endpoint.
- _`<TEMPO_OTLP_ENDPOINT>`_: The `host:port` of your Grafana Cloud Tempo endpoint.

With this configuration, Beyla instruments the `docs` service, and Alloy sends the traces to Grafana Cloud Traces and the metrics to Grafana Cloud Prometheus:

- The `attributes > kubernetes > enable` argument enables Kubernetes decoration for metrics and traces.
  Beyla adds the metadata of the Kubernetes entities that run the instrumented services.
- The `discovery > instrument > kubernetes` block selects the services to instrument based on Kubernetes metadata.
  In this example, Beyla instruments the `docs` Deployment in the `default` namespace.
- The `metrics > features` argument enables application metrics, such as request duration and request and response sizes.
- The `prometheus.scrape` component collects metrics from Beyla.
  The `honor_labels = true` setting keeps the `job` and `instance` labels that Beyla sets.
  The `prometheus.remote_write` component sends the metrics to Grafana Cloud Prometheus.
- The `output` block sends Beyla traces to the [`otelcol.exporter.otlp`][otelcol.exporter.otlp] component, which sends the traces to Grafana Cloud Traces.

For more information about the configuration options, refer to [`beyla.ebpf`][beyla.ebpf].

Create a ConfigMap from the file:

```sh
kubectl create configmap --namespace alloy alloy-config "--from-file=config.alloy=./config.alloy"
```

## Deploy Alloy with the Helm chart

Create a `values.yaml` file with the following overrides for the Alloy Helm chart:

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

These values configure the chart for Beyla:

- The `alloy.configMap` settings load the Alloy configuration from the `alloy-config` ConfigMap that you created.
- The `alloy.securityContext.privileged: true` setting gives the Alloy container the privileges that Beyla needs to load BPF programs and create BPF maps.
  Alloy runs Beyla as a child process inside the Alloy container.
- The `alloy.extraEnv` section sets the environment variables for the Prometheus and Tempo credentials from the `grafana-credentials` Secret.
- The `controller.type: daemonset` setting runs one Alloy Pod on each node, so Beyla can instrument processes on every node.
- The `controller.hostPID: true` setting gives Beyla access to all processes on the node.

This tutorial uses `privileged: true` for simplicity.
The Alloy documentation doesn't recommend privileged containers for production.
To run Alloy without `privileged: true`, refer to [Kubernetes: unprivileged, root user][alloy-unprivileged].

Install the Alloy Helm chart with these values:

```sh
helm install --namespace alloy alloy grafana/alloy -f values.yaml
```

Confirm that the Alloy Pods are running:

```sh
kubectl get pods --namespace alloy
```

The output lists one Alloy Pod for each node, with the status `Running`.

## Test the setup

With the `kubectl port-forward` commands still running, send requests to both web servers to generate telemetry:

```sh
curl http://localhost:8080
curl http://localhost:8080/foo
curl http://localhost:8081
curl http://localhost:8081/foo
```

Alloy scrapes Beyla metrics every 60 seconds by default, so data can take a minute or more to appear in Grafana Cloud.
If you don't see traces, wait a minute and send the requests again.

In Grafana Cloud, open **Explore** from the left panel and select the traces data source, named `grafanacloud-<USER_NAME>-traces`.

![Select the traces data source](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/k8s/select-traces.png)

To search for all the traces, select the **Search** box in the Query bar, leave the form empty, and click **Run query**:

![Searching for all the traces in the system](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/k8s/run-query.png)

The results show traces for the `docs` service, which you called on port 8081.
You don't see traces from the `website` service, because Beyla doesn't instrument it.
If other systems send traces to the same Grafana Cloud stack, you might also see their traces.

![Grafana Cloud list of traces](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/k8s/tut-traces-list.png)

In the trace details, the resource attributes include metadata of the Kubernetes Pod that runs the instrumented service:

![Details of the trace](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/k8s/tut-trace-details.png)

To check the metrics, select your Grafana Cloud Prometheus data source in **Explore** and run the following query:

```promql
http_server_request_duration_seconds_count{service_name="docs"}
```

## Next steps

- Learn about the metrics that Beyla exports in [Beyla exported metrics][metrics].
- Configure the component for your own services with the [`beyla.ebpf`][beyla.ebpf] reference.
- Run Alloy without privileged mode with [Kubernetes: unprivileged, root user][alloy-unprivileged].

[kind]: https://kind.sigs.k8s.io/
[requirements]: ../../#requirements
[helm]: https://helm.sh/
[pricing]: /pricing/
[metrics]: ../../metrics/
[otelcol.exporter.otlp]: /docs/alloy/latest/reference/components/otelcol/otelcol.exporter.otlp/
[beyla.ebpf]: /docs/alloy/latest/reference/components/beyla/beyla.ebpf/
[alloy-unprivileged]: /docs/alloy/latest/reference/components/beyla/beyla.ebpf/#kubernetes-unprivileged-root-user
