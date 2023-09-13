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

You can deploy Beyla in Kubernetes in two separate ways:

- As a Sidecar Container (recommended)
- As a DaemonSet

In the future, we will release a [Beyla operator](https://github.com/grafana/beyla-operator)
but at the moment it is work in progress and its API is not stable enough. 

## Deploying as a sidecar container

This is the recommended way of deploying Beyla for the following reason:

- You can configure the auto-instrumentation per instance, instead of having
  Beyla monitor all of the service instances on the host.
- You will save on compute and memory resources. If the auto-instrumented service is present only in a subset
  of the containers running on the host, you won't need to deploy the auto-instrument tool for all containers.

Deploying Beyla as a sidecar container has the following configuration
requirements:

- The process namespace must be shared between all containers in the Pod (`shareNamespace: true`
  pod variable)
- The auto-instrument tool must internally run as privileged user in the container
  (`securityContext.runAsUser: 0` property in the container configuration).
- The auto-instrument container must run in privileged mode (`securityContext.privileged: true` property of the
  container configuration) or at least with `SYS_ADMIN` capability (`securityContext.capabilities.add: ["SYS_ADMIN"])

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
        - name: autoinstrument
          image: grafana/beyla:latest
          securityContext: # Privileges are required to install the eBPF probes
            runAsUser: 0
            capabilities:
              add:
                - SYS_ADMIN
          env:
            - name: OPEN_PORT # The internal port of the goblog application container
              value: "8443"
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              value: "http://grafana-agent:4318"
```

For more information about the different configuration options, please check the
[Configuration]({{< relref "../configure/options.md" >}}) section of this documentation site.

Deploying as a sidecar container, is the default deployment mode for the
[eBPF auto-instrument Kubernetes Operator](https://github.com/grafana/beyla-operator).

## Deploying as a Daemonset

Alternatively, you can deploy the auto-instrumentation tool as a DaemonSet. Using the
previous example (the `goblog` pod), we cannot select the process to instrument by using
its open port, because the port is internal to the Pod. At the same time multiple instances of the
service would have different open ports. In this case, we will need to instrument by
using the application service executable name (see later example).

For security reasons, you should not deploy as DaemonSet unless you can be sure
that no external users can deploy pods to the Kubernetes cluster. This is to avoid
deploying a pod with a process whose name collides with the original instrumented
process.

In addition to the privilege requirements of the sidecar scenario,
you will need to configure the auto-instrument pod template with the `hostPID: true`
option enabled, so that it can access all of the processes running on the same host.

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
      hostPID: true # Require to access the processes on the host
      containers:
        - name: autoinstrument
          image: grafana/beyla:latest
          securityContext:
            runAsUser: 0
            privileged: true # Alternative to the capabilities.add SYS_ADMIN setting
          env:
            - name: EXECUTABLE_NAME # Select the executable by its name instead of OPEN_PORT
              value: "goblog"
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              value: "grafana-agent:4318"
```
