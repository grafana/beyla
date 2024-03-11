---
title: Beyla network metrics quickstart
menuTitle: Quickstart
description: A quickstart guide to produce Network Metrics from Grafana Beyla
weight: 2
keywords:
  - Beyla
  - eBPF
  - Network
---

# Beyla network metrics quickstart

> ⚠️ This is an unstable, under-development feature and might be subject to breaking changes in
> the short term. Use it at your own risk.

Beyla can generate network metrics in any environment (phisical host, virtual host or container), but
we currently recommend using this feature in Kubernetes, because it is the environment that, in the current status
of this feature, provides the most rich experience. Beyla is able to decorate each metric with the
metadata of the source and destination Kubernetes entities. 

## Deploying Beyla with network metrics

To enable network metrics, Beyla requires to set the `network -> enable: true` YAML option (or 
the `BEYLA_NETWORK_METRICS=true` environment variable). Check the 
[Beyla Network Metrics configuration options]({{< relref "../options" >}}) document for more
information about the configuration options that Beyla provides.

As previously explained, the `attributes -> kubernetes -> enable : true` YAML option (or the
`BEYLA_KUBE_METADATA_ENABLE=true` environment variable) are also required for a richer 
decoration of metrics.

Beyla Network metrics requires also some privileges. Either:

* Full privileged access (`root`, `sudo` or `privileged: true` in the case of Kubernetes).
* The following capabilities: `BPF`, `PERFMON`, `NET_ADMIN`, `SYS_RESOURCE`.

The following YAML would provide a basic Beyla deployment for network metrics:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: beyla
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: beyla
rules:
  - apiGroups: [ "apps" ]
    resources: [ "replicasets" ]
    verbs: [ "list", "watch" ]
  - apiGroups: [ "" ]
    resources: [ "pods", "services", "nodes" ]
    verbs: [ "list", "watch" ]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: beyla
subjects:
  - kind: ServiceAccount
    name: beyla
    namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: beyla
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: beyla-config
data:
  beyla-config.yml: |
    attributes:
      kubernetes:
        enable: true
    network:
      enable: true
      print_flows: true
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: beyla
spec:
  selector:
    matchLabels:
      instrumentation: beyla
  template:
    metadata:
      labels:
        instrumentation: beyla
    spec:
      serviceAccountName: beyla
      hostNetwork: true
      volumes:
        - name: beyla-config
          configMap:
            name: beyla-config
      containers:
        - name: beyla
          image: grafana/beyla:main
          securityContext:
            privileged: true
          volumeMounts:
            - mountPath: /config
              name: beyla-config
          env:
            - name: BEYLA_CONFIG_PATH
              value: "/config/beyla-config.yml"
```

Please notice the following requirements from the previous deployment:
* Beyla needs to run as a DaemonSet, as it is required one and only one Beyla instance per node.
* To allow Beyla decorating the network metrics with Kubernetes metadata,
  we had to create a `ClusterRole` and `ClusterRoleBinding` with _list_ and _watch_ permissions
  for ReplicaSets, Pods, Services and Nodes.
* To be able to listen to any packet in the host, Beyla requires the `hostNetwork: true` permission
  to be granted.
* The container image does not point to any release version but for the latest, under-development
  `grafana/beyla:main` image.

The previous YAML does not provide any endpoint for exporting the metrics. Instead, the `print_traces: true`
configuration option would print information in Beyla's standard output about the captured network flows:
groups of network packets between two endpoints.

After deploying the previous YAML, you can use `kubectl logs` to see each network flow in entries like
the following:

```
network_flow: beyla.ip=172.18.0.2 iface= direction=255 src.address=10.244.0.4 dst.address=10.96.0.1
src.name=local-path-provisioner-7577fdbbfb-g6b7d src.namespace=local-path-storage
dst.name=kubernetes dst.namespace=default k8s.src.host.ip=172.18.0.2
k8s.src.host.name=kind-control-plane k8s.dst.namespace=default k8s.dst.name=kubernetes
k8s.dst.owner.type=Service k8s.src.namespace=local-path-storage
k8s.src.name=local-path-provisioner-7577fdbbfb-g6b7d k8s.src.type=Pod
k8s.src.owner.name=local-path-provisioner k8s.src.owner.type=Deployment
k8s.dst.type=Service k8s.dst.owner.name=kubernetes
```

The [Network Metrics]({{< relref "../" >}}) main page describes each of the above attributes.

## Configure OTEL exporter

After running Beyla in network metrics mode and verify in its standard output that it is able
to capture network information, Beyla needs to be configured to export the metrics in OpenTelemetry
format.

> ⚠️ Prometheus metrics export is not yet supported.

Despite working with any standard OpenTelemetry endpoint, for this quickstart we recommend using
the OpenTelemetry endpoint in Grafana Cloud. You can get a [Free Grafana Cloud Account at Grafana's website](/pricing/).

From the Grafana Cloud Portal, look for the **OpenTelemetry** box and click **Configure**.

![OpenTelemetry Grafana Cloud portal](https://grafana.com/media/docs/grafana-cloud/beyla/quickstart/otel-cloud-portal-box.png)

Under **Password / API token** click **Generate now** and follow the instructions to create a default API token.

The **Environment Variables** will be populated with a set of standard OpenTelemetry environment variables which will provide the connection endpoint and credentials information for Beyla.

![OTLP connection headers](https://grafana.com/media/docs/grafana-cloud/beyla/quickstart/otlp-connection-headers.png)

Copy the value of `OTEL_EXPORTER_OTLP_HEADERS` environment variable and paste it as a Kubernetes
secret (and deploy it):
```
apiVersion: v1
kind: Secret
metadata:
  name: grafana-secret
type: Opaque
stringData:
  otlp-headers: "Authorization=Basic MzQ3NTp....."
```

Now add the `OTEL_EXPORTER_OTLP_HEADERS` and reference this secret as the variable value.
Also Add `OTEL_EXPORTER_OTLP_ENDPOINT` and its value as an environment variable to the Beyla
container in the Kubernetes manifest. The `env` section of the `beyla` container in the
manifest from the start of this document should look like:

```yaml
          env:
            - name: BEYLA_CONFIG_PATH
              value: "/config/beyla-config.yml"
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              value: "https://otlp-gateway-prod-eu-west-0.grafana.net/otlp"
            - name: OTEL_EXPORTER_OTLP_HEADERS
              valueFrom:
                secretKeyRef:
                  key: otlp-headers
                  name: grafana-secret
```

## Select metrics attributes to reduce cardinality


## Group IPs by CIDR