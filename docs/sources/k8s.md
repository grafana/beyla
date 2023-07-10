---
title: Deploy in Kubernetes
---

# Deploy in Kubernetes

In Kubernetes, you can Deploy the eBPF Autoinstrument in two ways:

* As a Sidecar Container (recommended)
* As a DaemonSet

## Deploying as a Sidecar Container

This is the recommended way of deploying the eBPF autoinstrument by some reasons:

* You can configure the autoinstrumentation per instance, instead of having a single
  Autoinstrument per all the instances in the host.
* You will save resources. If the autoinstrumented service is present only in a subset
  of the host, you don't need to deploy the eBPF Autoinstrument in all the hosts.

Deploying the eBPF autoinstrument as a Sidecar container requires the following
configuration:

* Share the process namespace between all the containers in the Pod (`shareNamespace: true`
  Pod variable)
* Internally run as privileged user of the container (`securityContext.runAsUser: 0` property
  in the Container configuration).
* Run the container as privileged (`securityContext.privileged: true` property of the
  Container configuration) or at least with `SYS_ADMIN` capability (`securityContext.capabilities.add: ["SYS_ADMIN"])

Following example instruments a `goblog` Pod by attaching the eBPF Autoinstrument
as a container (image available at `grafana/ebpf-autoinstrument:latest`). The
Autoinstrument is configured to forward metrics and traces to a Grafana Agent
that is accessible behind the `grafana-agent` service in the same namespace: 

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
      # required so the sidecar instrumenter can access the service process
      shareProcessNamespace: true
      containers:
        # Container for the instrumented service
        - name: goblog
          image: mariomac/goblog:dev
          imagePullPolicy: IfNotPresent
          command: [ "/goblog" ]
          env:
            - name: "GOBLOG_CONFIG"
              value: "/sample/config.yml"
          ports:
            - containerPort: 8443
              name: https
        # Sidecar container with the eBPF AutoInstrument
        - name: autoinstrument
          image: grafana/ebpf-autoinstrument:latest
          securityContext: # Privileges are required to operate with eBPF
            runAsUser: 0
            capabilities:
              add:
                - SYS_ADMIN
          env:
            - name: OPEN_PORT # Pointing to the internal port of the container
              value: "8443"
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              value: "http://grafana-agent:4318"
```

For more information about the different configuration options, please check the
[Configuration]({{< relref "./config" >}}) document.

Deploying as a sidecar is the chosen option by the work-in-progress
[eBPF Autoinstrument Operator](https://github.com/grafana/ebpf-autoinstrument-operator).

## Deploying as a Daemonset

Alternatively, you can deploy the operator as a DaemonSet. In the case of the
previous example (the `goblog` Pod), you cannot select the process by open port,
because the port is internal to the Pod, and because multiple instances o the
service would use different node ports. In this case, you need to select it by
executable name (see later example).

For security reasons, you should not deploy as DaemonSet unless you can be sure
that no external users can deploy pods to the Kubernetes cluster, to avoid
deploying a Pod with a process whose name collides with the original instrumented
process.

In addition to the same privileges requirements as for the Sidecar scenario,
you need to configure the Autoinstrument pod template with the `hostPID: true`
option enabled, so it can access all the processes running in the same host.

```yaml
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ebpf-autoinstrument
  labels:
    app: ebpf-autoinstrument
spec:
  selector:
    matchLabels:
      app: ebpf-autoinstrument
  template:
    metadata:
      labels:
        app: ebpf-autoinstrument
    spec:
      hostPID: true # require to access processes in the host
      containers:
        - name: autoinstrument
          image: grafana/ebpf-autoinstrument:latest
          securityContext:
            runAsUser: 0
            privileged: true # alternative to capabilities.add
          env:
            - name: EXECUTABLE_NAME  # Select executable by name instead of port
              value: "goblog"
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              value: "grafana-agent:4318"
```
