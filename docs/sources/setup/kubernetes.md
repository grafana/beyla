---
title: Deploy Beyla in Kubernetes
menuTitle: Deploy in Kubernetes
description: Learn how to deploy Beyla in Kubernetes.
weight: 3
keywords:
  - Beyla
  - eBPF
  - Kubernetes
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/setup/kubernetes/
---

# Deploy Beyla in Kubernetes

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

## Configuring Kubernetes metadata decoration

Beyla can decorate your traces with the following Kubernetes labels:

- `k8s.namespace.name`
- `k8s.deployment.name`
- `k8s.statefulset.name`
- `k8s.replicaset.name`
- `k8s.daemonset.name`
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

{{< youtube id="d7clTdz0bA4" >}}

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

### Deploy Beyla Unprivileged

In all of the examples so far, `privileged:true` was used in the Beyla deployment
`securityContext` section. While this works in all circumstances, there are ways
to deploy Beyla in Kubernetes with reduced privileges, if your security configuration
requires you to do so. Whether it is possible to run Beyla without `privileged:true`,
depends a lot on the Kubernetes version you have and the underlying container 
runtime used (e.g. **Containerd**, **CRI-O** or **Docker**).

The following guide is based on tests performed mainly by running `containerd` with
`kubeadm`, `k3s`, `microk8s` and `kind`.

To run Beyla unprivileged, you need to replace the `privileged:true` setting with a
set of Linux [capabilities](https://www.man7.org/linux/man-pages/man7/capabilities.7.html).
The two main capabilities which Beyla needs are `CAP_SYS_ADMIN` and `CAP_SYS_PTRACE`. On
kernel versions before **5.11**, `CAP_SYS_RESOURCE` is also required. 

- `CAP_SYS_ADMIN` is required to install most of Beyla's eBPF probes, because Beyla tracks system calls.
- `CAP_SYS_PTRACE` is required so that Beyla is able to look into the processes namespaces and inspect the executables.
  Beyla doesn't use `ptrace`, but some of the operations it does require this capability.
- `CAP_SYS_RESOURCE` is required only on kernels **< 5.11** so that Beyla can increase the amount of locked memory available.

In addition to these Linux capabilities, many Kubernetes versions include [AppArmour](https://kubernetes.io/docs/tutorials/security/apparmor/),
which though policies adds additional restrictions to unprivileged containers. 
By [default](https://github.com/moby/moby/blob/master/profiles/apparmor/template.go), the AppArmour 
policy restricts the use of `mount` and the access to `/sys/fs/` directories. Beyla uses the BPF Linux file system
to store pinned BPF maps, for communication among the different BPF programs. For this reason, Beyla
either needs to `mount` a BPF file system, or write to `/sys/fs/bpf`, which are both restricted.

Because of the AppArmour restriction, to run Beyla as unprivileged container, you need to either:

- Set `container.apparmor.security.beta.kubernetes.io/beyla: "unconfined"` in your Kubernetes deployment files.
- Set a modified AppArmour policy which allows Beyla to perform `mount`.

An example of a Beyla unprivileged container configuration can be found below, or you can download
the [full example deployment](https://github.com/grafana/beyla/tree/main/examples/k8s/unprivileged.yaml) file:

```yaml
...
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: beyla
  namespace: beyla-demo
  labels:
    k8s-app: beyla
spec:
  selector:
    matchLabels:
      k8s-app: beyla
  template:
    metadata:
      labels:
        k8s-app: beyla
      annotations:
        # We need to set beyla container as unconfined so it is able to write
        # the BPF file system.
        # Instead of 'unconfined', you can define a more refined policy which allows Beyla to use 'mount' 
        container.apparmor.security.beta.kubernetes.io/beyla: "unconfined" # <-- Important
    spec:
      serviceAccount: beyla
      hostPID: true           # <-- Important. Required in Daemonset mode so Beyla can discover all monitored processes 
      containers:
      - name: beyla
        terminationMessagePolicy: FallbackToLogsOnError
        image: "docker.io/grafana/beyla:main"
        imagePullPolicy: "Always"
        command: [ "/beyla" ]
        env:
          - name: BEYLA_PRINT_TRACES
            value: "true"
          - name: BEYLA_KUBE_METADATA_ENABLE
            value: "autodetect"
          ...
        securityContext:
          runAsUser: 0
          readOnlyRootFilesystem: true
          capabilities:
            add:
              - SYS_ADMIN     # <-- Important. Required for most eBPF probes to function correctly.
              - SYS_PTRACE    # <-- Important. Allows Beyla to access the container namespaces and inspect executables.
              #- SYS_RESOURCE # <-- pre 5.11 only. Allows Beyla to increase the amount of locked memory.
        volumeMounts:
        - name: var-run-beyla
          mountPath: /var/run/beyla
        - name: cgroup
          mountPath: /sys/fs/cgroup
      tolerations:
      - effect: NoSchedule
        operator: Exists
      - effect: NoExecute
        operator: Exists
      volumes:
      - name: var-run-beyla
        emptyDir: {}      
      - name: cgroup
        hostPath:
          path: /sys/fs/cgroup
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: some-service
  namespace: beyla-demo
  ...
---          

```


## Providing an external configuration file

In the previous examples, Beyla was configured via environment variables.
However, you can also configure it via an external YAML file (as documented
in the [Configuration]({{< relref "../configure/options.md" >}}) section of
this site).

To provide the configuration as a file, the recommended way is to deploy
a ConfigMap with the intended configuration, then mount it into the Beyla
Pod, and refer to it with the `BEYLA_CONFIG_PATH` environment variable.

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
      hostPID: true #important!
      containers:
        - name: beyla
          image: grafana/beyla:latest
          imagePullPolicy: IfNotPresent
          securityContext:
            privileged: true
            readOnlyRootFilesystem: true
          # mount the previous ConfigMap as a folder
          volumeMounts:
            - mountPath: /config
              name: beyla-config
            - mountPath: /var/run/beyla
              name: var-run-beyla
          env:
            # tell beyla where to find the configuration file
            - name: BEYLA_CONFIG_PATH
              value: "/config/beyla-config.yml"
      volumes:
        - name: beyla-config
          configMap:
            name: beyla-config
        - name: var-run-beyla
          emptyDir: {}
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
