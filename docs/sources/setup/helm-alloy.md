---
title: Run Beyla in Kubernetes using Grafana Alloy Helm's chart
menuTitle: Grafana Alloy Helm chart
description: Learn how to instrument an application export data with Prometheus to Grafana Cloud
weight: 600
keywords:
  - Beyla
  - eBPF
  - Kubernetes
  - Alloy
  - tutorial
aliases:
  - /docs/beyla/latest/tutorial/helm-alloy/
---

# Run Beyla in Kubernetes using Grafana Alloy Helm's chart

Grafana Alloy is a vendor-neutral distribution of the OpenTelemetry Collector.
Alloy offers native pipelines for OpenTelemetry, Prometheus, and other telemetry signals.

Grafana Alloy bundles Beyla allowing you to instrument your applications at the same time
you instrument your infrastructure. It also provides a Helm chart to deploy Alloy in Kubernetes.

In this tutorial, you learn how to deploy Beyla in Kubernetes using Grafana Alloy Helm's chart.

## Prerequisites

- A Kubernetes cluster, you can use [kind](https://kind.sigs.k8s.io/) to create a local cluster
- `kubectl` installed and configured for your cluster
- [Helm](https://helm.sh/) installed
- A Grafana Cloud account or a compatible Prometheus and/or OpenTelemetry backend to receive the data

### 1. Prepare the Alloy environment in Kubernetes

Add the Grafana Helm chart repository, update it, and create the `alloy` namespace:

```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
kubectl create namespace alloy
```

You install the Alloy Helm chart in this namespace after you create the credentials and the Alloy configuration.

### 2. Deploy services

You can instrument any HTTP or HTTPS service in your Kubernetes cluster.

Copy the following contents into a file, for example `sampleapps.yml`, and deploy it with
the command `kubectl apply -f sampleapps.yml`.

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

### 3. Configure credentials

Alloy can export metrics and traces to any OpenTelemetry endpoint, as well as exposing metrics as a Prometheus endpoint. However, it's recommend using the Prometheus and Tempo remote write endpoints in Grafana Cloud. You can get a [free Grafana Cloud Account](/pricing/).

From the Grafana Cloud Portal, look for the **Prometheus** box and click **Send Metrics**. For the **Tempo** box, click **Send Traces**.

Create a `secrets.yml` file with your Grafana Cloud credentials for Prometheus and Tempo remote write. Deploy it with the command `kubectl apply -f secrets.yml`.

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

### 3. Create a ConfigMap with Alloy configuration

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

- _`<PROMETHEUS_REMOTE_WRITE_URL>`_: The Prometheus remote write URL of your Grafana Cloud stack, which ends in `/api/prom/push`
- _`<TEMPO_ENDPOINT>`_: The Tempo endpoint of your Grafana Cloud stack, including the `:443` port

Deploy the configuration with the command:

```bash
kubectl create configmap --namespace alloy alloy-config "--from-file=config.alloy=./config.alloy"
```

With this configuration Beyla instruments the services running in the Kubernetes cluster and send traces to Grafana Cloud Tempo and metrics to Prometheus.

The `attributes > kubernetes > enable` enables Kubernetes decoration for metrics and traces, which adds the metadata of the Kubernetes entities running the automatically instrumented services.

The `discovery > instrument > kubernetes` block selects the services to instrument by their Kubernetes metadata, with glob patterns. In this example, Beyla instruments only the `docs` Deployment in the `default` namespace.

The `prometheus.scrape` section configures Prometheus scrape to collect metrics from Beyla. The `honor_labels = true` setting preserves the per-process instance identifiers set by Beyla. The `prometheus.remote_write` section sends the metrics to Grafana Cloud Prometheus.

The `output` section configures that Beyla component sends traces to `otelcol.exporter.otlp` component. The `otelcol.exporter.otlp` section configures the [OTLP exporter](/docs/alloy/latest/reference/components/otelcol.exporter.otlp) to send the traces to Grafana Cloud Tempo.

For further details on the configuration options, refer to the documentation of the [Grafana Alloy Beyla component](/docs/alloy/latest/reference/components/beyla.ebpf)

### 4. Deploy Alloy with Helm

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
- The `extraEnv` section sets the environment variables for the Prometheus and Tempo remote write credentials.

### 5. Test the setup

With the `kubectl port-forward` commands from the first step still running,
test both web server instances. For example:

```sh
curl http://localhost:8080
curl http://localhost:8080/foo
curl http://localhost:8081
curl http://localhost:8081/foo
```

Navigate to the instance in Grafana Cloud, and from the **Explore** section in the left panel, select the data source for the traces, named `grafanacloud-<your user name>-traces`.

![Select the traces data source](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/k8s/select-traces.png)

To search for all the traces, select the **Search** box in the Query bar, leave the form empty, and click **Run query**:

![Searching for all the traces in the system](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/k8s/run-query.png)

This shows the traces for the `docs` instance on port 8081. You might see traces from your own services, but you shouldn't see traces from the `website` service, as it Beyla isn't instrumenting it.

![Grafana Cloud list of traces](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/k8s/tut-traces-list.png)

In the trace details, the resource attributes of the traces have metadata of the Kubernetes Pod running the instrumented service:

![Details of the trace](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/k8s/tut-trace-details.png)
