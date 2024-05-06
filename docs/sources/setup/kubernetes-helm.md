---
title: Deploy Beyla in Kubernetes with Helm
menuTitle: Deploy in Kubernetes with Helm
description: Learn how to deploy Beyla as a Helm chart in Kubernetes.
weight: 3
keywords:
  - Beyla
  - eBPF
  - Kubernetes
  - Helm
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/setup/kubernetes-helm/
---

# Deploy Beyla in Kubernetes with Helm

For a step-by-step walkthrough by the basics for Beyla and Kubernetes, you can also
follow the [Beyla and Kubernetes walkthrough tutorial]({{< relref "../tutorial/k8s-walkthrough.md" >}}).

Contents:

<!-- TOC -->

- [Deploy Beyla in Kubernetes](#deploy-beyla-in-kubernetes)
  - [Configuring Kubernetes metadata decoration](#configuring-kubernetes-metadata-decoration)
  - [Deploying Beyla](#deploying-beyla)
    - [Deploy Beyla as a sidecar container](#deploy-beyla-as-a-sidecar-container)
    - [Deploy Beyla as a Daemonset](#deploy-beyla-as-a-daemonset)
    - [Deploy Beyla unprivileged](#deploy-beyla-unprivileged)
  - [Providing an external configuration file](#providing-an-external-configuration-file)
  - [Providing secret configuration](#providing-secret-configuration)
  <!-- TOC -->

## Deploying Beyla from helm

First, you need to add the Grafana helm repository to Helm:

```
helm repo add grafana https://grafana.github.io/helm-charts
```

The following command deploys a Beyla DaemonSet with a default configuration in the `beyla` namespace:

```
helm install beyla -n beyla --create-namespace  grafana/beyla
```

The default Beyla configuration is provided so:

* Exports the metrics as Prometheus metrics in the Pod HTTP port `9090`, `/metrics` path.
* It tries to instrument all the applications in your cluster.
* It will provide only application-level metrics. [Network-level metrics]({{< relref "../network" >}}) are excluded by default.
* Configures Beyla to decorate the metrics with Kubernetes metadata labels (`k8s.namespace.name`, `k8s.pod.name`, etc.).

## Configuring Beyla 

You might want to override the default configuration of Beyla. For example, to export the metrics and/or spans
as OpenTelemetry instead of Prometheus, or to restrict the number of services to instrument.

You can override te default [Beyla configuration options]({{< relref "../configure" >}}) with your own values:


## Configuring Beyla labels

## Providing secret configuration

The previous example is valid for regular configuration but should not be
used to pass secret information like passwords or API keys.

To provide secret information, the recommended way is to deploy a Kubernetes
Secret. For example, this secret contains some fictional Grafana Cloud
credentials:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: grafana-secret
type: Opaque
stringData:
  grafana-user: "123456"
  grafana-api-key: "xxxxxxxxxxxxxxx"
```

Then you can access the secret values as environment variables. Following the
previous DaemonSet example, this would be achieved by adding the following
`env` section to the Beyla container:

```yaml
env:
  - name: GRAFANA_CLOUD_ZONE
    value: prod-eu-west-0
  - name: GRAFANA_CLOUD_INSTANCE_ID
    valueFrom:
      secretKeyRef:
        key: grafana-user
        name: grafana-secret
  - name: GRAFANA_CLOUD_API_KEY
    valueFrom:
      secretKeyRef:
        key: grafana-api-key
        name: grafana-secret
```

## More configuration options

https://github.com/grafana/beyla/blob/main/charts/beyla/README.md
