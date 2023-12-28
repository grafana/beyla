---
title: Deploy Beyla in Kubernetes
menuTitle: Deploy in Kubernetes
description: Learn how to deploy Beyla in Kubernetes.
weight: 3
keywords:
  - Beyla
  - eBPF
  - Kubernetes
---

# Deploy Beyla in Kubernetes

Contents:

<!-- TOC -->
* [Deploy Beyla in Kubernetes](#deploy-beyla-in-kubernetes)
  * [Configuring Kubernetes metadata decoration](#configuring-kubernetes-metadata-decoration)
  * [Deploying Beyla](#deploying-beyla)
    * [Deploy Beyla as a sidecar container](#deploy-beyla-as-a-sidecar-container)
    * [Deploy Beyla as a Daemonset](#deploy-beyla-as-a-daemonset)
  * [Providing an external configuration file](#providing-an-external-configuration-file)
  * [Providing secret configuration](#providing-secret-configuration)
<!-- TOC -->

## Configuring Kubernetes metadata decoration

Beyla can decorate your traces with the following Kubernetes labels:

- `k8s.namespace.name`
- `k8s.deployment.name`
- `k8s.node.name`
- `k8s.pod.name`
- `k8s.pod.uid`
- `k8s.pod.start_time`

To enable metadata decoration, you need to:
- Create a ServiceAccount and bind a ClusterRole granting list and watch permissions
  for both Pods and ReplicaSets. You can do it by deploying this example file:

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
  - apiGroups: ["apps"]
    resources: ["replicasets"]
    verbs: ["list", "watch"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list", "watch"]
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
```

(You need to change the `namespace: default` value if you are deploying Beyla
in another namespace).

2. Configure Beyla with the `BEYLA_KUBE_METADATA_ENABLE=true` environment variable,
  or the `attributes.kubernetes.enable: true` YAML configuration.

3. Don't forget to specify the `serviceAccountName: beyla` property in your Beyla
   Pod (as shown in the later deployment examples).

Optionally, select which Kubernetes services to instrument in the `discovery -> services`
section of the YAML configuration file. For more information, refer to the
_Service discovery_ section in the [Configuration document]({{< relref "../configure/options.md" >}}),
as well as the [Providing an external configuration file](#providing-an-external-configuration-file)
section of this page.

## Deploying Beyla

You can deploy Beyla in Kubernetes in two different ways:

- As a sidecar container
- As a DaemonSet

### Deploy Beyla as a sidecar container

This is the way you can deploy Beyla if you want to monitor a given service that
might not be deployed in all the hosts, so you only have to deploy one Beyla instance
per each service instance.

Deploying Beyla as a sidecar container has the following configuration
requirements:

- The process namespace must be shared between all containers in the Pod (`shareProcessNamespace: true`
  pod variable)
- The auto-instrument container must run in privileged mode (`securityContext.privileged: true` property of the
  container configuration).
  - Some Kubernetes installation allow the following `securityContext` configuration,
    but it might not work with all the container runtime configurations, as some of them confine
    the containers and remove some permissions:
    ```yaml
    securityContext:
      runAsUser: 0
      capabilities:
        add:
          - SYS_ADMIN
          - SYS_RESOURCE # not required for kernels 5.11+
    ```

The following example instruments the `goblog` pod by attaching Beyla
as a container (image available at `grafana/beyla:latest`). The
auto-instrumentation tool is configured to forward metrics and traces to a Grafana Agent,
which is accessible behind the `grafana-agent` service in the same namespace:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: goblog
  labels:
    app: goblog
spec:
  replicas: 2
  selector:
    matchLabels:
      app: goblog
  template:
    metadata:
      labels:
        app: goblog
    spec:
      # Required so the sidecar instrument tool can access the service process
      shareProcessNamespace: true
      serviceAccountName: beyla # required if you want kubernetes metadata decoration
      containers:
        # Container for the instrumented service
        - name: goblog
          image: mariomac/goblog:dev
          imagePullPolicy: IfNotPresent
          command: ["/goblog"]
          env:
            - name: "GOBLOG_CONFIG"
              value: "/sample/config.yml"
          ports:
            - containerPort: 8443
              name: https
        # Sidecar container with Beyla - the eBPF auto-instrumentation tool
        - name: beyla
          image: grafana/beyla:latest
          securityContext: # Privileges are required to install the eBPF probes
            privileged: true
          env:
            # The internal port of the goblog application container
            - name: BEYLA_OPEN_PORT
              value: "8443"
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              value: "http://grafana-agent:4318"
              # required if you want kubernetes metadata decoration
            - name: BEYLA_KUBE_METADATA_ENABLE
              value: "true"
```

For more information about the different configuration options, please check the
[Configuration]({{< relref "../configure/options.md" >}}) section of this documentation site.

### Deploy Beyla as a Daemonset

You can also deploy Beyla as a Daemonset. This is the preferred way if:
- You want to instrument a Daemonset
- You want to instrument multiple processes from a single Beyla instance, or even
  all the instrumentable processes in your cluster.

Using the previous example (the `goblog` pod), we cannot select the process
to instrument by using its open port, because the port is internal to the Pod.
At the same time multiple instances of the
service would have different open ports. In this case, we will need to instrument by
using the application service executable name (see later example).

In addition to the privilege requirements of the sidecar scenario,
you will need to configure the auto-instrument pod template with the `hostPID: true`
option enabled, so that it can access all the processes running on the same host.

```yaml
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: beyla
  labels:
    app: beyla
spec:
  selector:
    matchLabels:
      app: beyla
  template:
    metadata:
      labels:
        app: beyla
    spec:
      hostPID: true # Required to access the processes on the host
      serviceAccountName: beyla # required if you want kubernetes metadata decoration
      containers:
        - name: autoinstrument
          image: grafana/beyla:latest
          securityContext:
            runAsUser: 0
            privileged: true
          env:
            # Select the executable by its name instead of BEYLA_OPEN_PORT
            - name: BEYLA_EXECUTABLE_NAME
              value: "goblog"
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              value: "http://grafana-agent:4318"
              # required if you want kubernetes metadata decoration
            - name: BEYLA_KUBE_METADATA_ENABLE
              value: "true"
```

## Providing an external configuration file

In the previous examples, Beyla was configured via environment variables.
However, you can also configure it via an external YAML file (as documented
in the [Configuration]({{< relref "../configure/options.md" >}}) section of
this site).

To provide the configuration as a file, the recommended way is to deploy
a ConfigMap with the intended configuration, then mount it into the Beyla
Pod, and refer to it by overriding the Beyla container command.

Example of ConfigMap with the Beyla YAML documentation:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: beyla-config
data:
  beyla-config.yml: |
    print_traces: true
    grafana:
      otlp:
        submit: ["metrics","traces"]
    otel_traces_export:
      sampler:
        name: parentbased_traceidratio
        arg: "0.01"
    routes:
      patterns:
        - /factorial/{num}
```

Example of Beyla DaemonSet configuration, mounting and accessing to the
previous ConfigMap:

```yaml
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
      hostPID: true  #important!
      volumes:
        - name: beyla-config
          configMap:
            name: beyla-config
      containers:
        - name: beyla
          image: grafana/beyla:latest
          imagePullPolicy: IfNotPresent
          securityContext:
            privileged: true
          # mount the previous ConfigMap as a folder
          volumeMounts:
            - mountPath: /config
              name: beyla-config
          # tell beyla where to find the configuration file
          command: ["/beyla", "--config=/config/beyla-config.yml"]
```

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

