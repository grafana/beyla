---
title: Cilium compatibility
menuTitle: Cilium compatibility
description: Compatibility notes when running Beyla alongside Cilium
weight: 22
keywords:
  - Beyla
  - eBPF
  - distributed traces
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/cilium-compatibility/
---

# Cilium compatibility

## Introduction

[Cilium](https://cilium.io) is an open source cloud native solution for providing, securing, and observing network connectivity between workloads. In some cases the eBPF programs Cilium uses can conflict with the ePBF programs Beyla uses and lead to system disruptions and instability.

Beyla and Cilium use eBPF traffic control classifier programs, `BPF_PROG_TYPE_SCHED_CLS`. These programs attach to the ingress and egress data paths of the kernel networking stack. Together they form a chain of _packet filters_. Each packet filter is able to inspect the contents of the packet and perform operations, for example redirect or discard the packet. Beyla programs never disrupt the flow of a packet, Cilium changes packet flow as part of its operation. If Cilium processes packets before Beyla it can affect its ability to visualize and process packets.

Beyla is capable of detecting whether Cilium is running and registers its traffic control programs at the head of the program chain ensuring they run before any other eBPF program. Beyla observes packets before handing them over to the next program in the chain, for example Cilium. If that isn't possible, Beyla exits with an appropriate error message.

## TCX and netlink attachments

Beyla uses the TCX (Traffic Control eXpress) API or the netlink interface in the Linux Kernel to attach traffic control (TC) programs. The TCX API is in kernel since version 6 and is the preferred method to attach TC programs. It provides a linked list mechanism to attach programs to the _head_, the _middle_, or the _tail_. Beyla and Cilium auto-detect if the kernel supports TCX and use it by default.

When Beyla and Cilium uses TCX they can coexist without interfering. Beyla attaches its eBPF programs to the head of the list and Cilium to the tail. TCX is the preferred operation mode when possible.

The legacy _netlink_ interface relies on _clsact_  [_qdiscs_](https://tldp.org/HOWTO/Traffic-Control-HOWTO/components.html) and a special type of tc filter (called bpf filter) to attach eBPF programs to network interfaces. Unlike TCX, there's no unique _linked list_ semantics (although filter chaining is possible), but in a simplistic manner, filters are executed according to their configured priority (the lower the priority number, the higher the priority, with 1 being the highest priority). If two filters have the same priority, then they follow a _LIFO_ approach in which the last attached filter runs first.

When _TCX_ is not available, both Beyla and Cilium use `netlink` interface to install eBPF programs with a priority of 1, which can become problematic, specially if Cilium does that after Beyla. Therefore, a few precautions are due in this scenario.

## Deploy Beyla and Cilium using `netlink` attachments

A simple solution to ensure the healthy coexistence of Beyla and Cilium when the `netlink` interface is being used for traffic control program attachment is to configure Cilium to use a priority of _2_ for its traffic control eBPF programs. The priority is controlled via the `bpf-filter-priorty` configuration, and can be set like this:
```
cilium config set bpf-filter-priority 2
```
This ensures that Beyla's programs always run before Cilium's.

## Mixed TCX and netlink

In the very odd scenario in which both TCX and netlink attachments are being used, TCX programs _always_ run before those attached via the `netlink` interface.

## Summary of the possible modes of operation

When Beyla is using TCX, there's nothing to be done and it works out of the box, even if Cilium is using netlink.

When both Beyla and Cilium are relying on netlink attachments, Beyla checks if Cilium's priority is greater than _1_ to avoid problems. If Beyla detects Cilium programs are running exclusively with priority _1_, Beyla refuses to run and displays an error message instead.

Beyla also refuses to run if it is configured to use `netlink` attachments but it detects Cilium is using TCX.

## Beyla attachment mode configuration

Beyla TC attachment mode can be configured using the `BEYLA_BPF_TC_BACKEND` configuration option [as described here.](https://grafana.com/docs/beyla/latest/configure/options/).

Cilium can be configured via the `enable-tcx` boolean configuration option.

## Beyla and Cilium Trace Context Propagation Kubernetes Demo

Here we present a minimalist demo showing Beyla and Cilium working together.

### Install Cilium

Install Cilium to a **_kind_** hosted Kubernetes container as [described here](https://docs.cilium.io/en/stable/gettingstarted/k8s-install-default/).

If the kernel you deployed Cilium does not support TCX, configure Cilium to use priority 2 for its eBPF programs:

```
cilium config set bpf-filter-priority 2
```

### Deploy sample services

Use the following definition to deploy the same services. These are very small toy services that talk to one another, allowing us to show Beyla working with trace-context propagation:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nodejs-deployment
  labels:
    app: node
spec:
  replicas: 1
  selector:
    matchLabels:
      app: node
  template:
    metadata:
      labels:
        app: node
    spec:
      containers:
        - name: node
          image: ghcr.io/grafana/beyla-test/nodejs-testserver
          ports:
            - containerPort: 3030
              hostPort: 3030
---
apiVersion: v1
kind: Service
metadata:
  name: node-service
spec:
  type: NodePort
  selector:
    app: node
  ports:
    - name: node
      protocol: TCP
      port: 30030
      targetPort: 3030
      nodePort: 30030
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: go-deployment
  labels:
    app: go-testserver
spec:
  replicas: 1
  selector:
    matchLabels:
      app: go-testserver
  template:
    metadata:
      labels:
        app: go-testserver
    spec:
      containers:
        - name: go-testserver
          image: ghcr.io/grafana/beyla-test/go-testserver
          ports:
            - containerPort: 8080
              hostPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: testserver
spec:
  type: NodePort
  selector:
    app: go-testserver
  ports:
    - name: go-testserver
      protocol: TCP
      port: 8080
      targetPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: python-deployment
  labels:
    app: python-testserver
spec:
  replicas: 1
  selector:
    matchLabels:
      app: python-testserver
  template:
    metadata:
      labels:
        app: python-testserver
    spec:
      containers:
        - name: python-testserver
          image: ghcr.io/grafana/beyla-test/python-testserver
          ports:
            - containerPort: 8083
              hostPort: 8083
---
apiVersion: v1
kind: Service
metadata:
  name: pytestserver
spec:
  type: NodePort
  selector:
    app: python-testserver
  ports:
    - name: python-testserver
      protocol: TCP
      port: 8083
      targetPort: 8083
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rails-deployment
  labels:
    app: rails-testserver
spec:
  replicas: 1
  selector:
    matchLabels:
      app: rails-testserver
  template:
    metadata:
      labels:
        app: rails-testserver
    spec:
      containers:
        - name: rails-testserver
          image: ghcr.io/grafana/beyla-test/rails-testserver
          ports:
            - containerPort: 3040
              hostPort: 3040
---
apiVersion: v1
kind: Service
metadata:
  name: utestserver
spec:
  type: NodePort
  selector:
    app: rails-testserver
  ports:
    - name: rails-testserver
      protocol: TCP
      port: 3040
      targetPort: 3040
```

### Deploy Beyla

#### Create the Beyla namespace

```
kubectl create namespace beyla
```

#### Apply permissions

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  namespace: beyla
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
    namespace: beyla
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: beyla
```

#### Deploy Beyla

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: beyla
  name: beyla-config
data:
  beyla-config.yml: |
    attributes:
      kubernetes:
        enable: true
    routes:
      unmatched: heuristic
    # let's instrument only the docs server
    discovery:
      services:
        - k8s_deployment_name: "nodejs-deployment"
        - k8s_deployment_name: "go-deployment"
        - k8s_deployment_name: "python-deployment"
        - k8s_deployment_name: "rails-deployment"
    trace_printer: text
    ebpf:
      enable_context_propagation: true
      traffic_control_backend: tcx
      disable_blackbox_cp: true
      track_request_headers: true
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  namespace: beyla
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
      hostPID: true
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      containers:
        - name: beyla
          image: grafana/beyla:main
          securityContext:
            privileged: true
            readOnlyRootFilesystem: true
          volumeMounts:
            - mountPath: /config
              name: beyla-config
            - mountPath: /var/run/beyla
              name: var-run-beyla
          env:
            - name: BEYLA_CONFIG_PATH
              value: "/config/beyla-config.yml"
      volumes:
        - name: beyla-config
          configMap:
            name: beyla-config
        - name: var-run-beyla
          emptyDir: {}
```

#### Forward a port to the host and trigger a request

```
kubectl port-forward services/node-service 30030:30030 &
curl http://localhost:30030/traceme
```

#### Check your Beyla Pod logs

```
for i in `kubectl get pods -n beyla -o name | cut -d '/' -f2`; do kubectl logs -n beyla $i | grep "GET " | sort; done
```

You should obtain an output showing the requests detected by Beyla with trace-context propagation similar to this:

```
2025-01-17 21:42:18.11794218 (5.045099ms[5.045099ms]) HTTPClient 200 GET /tracemetoo [10.244.1.92 as go-deployment.default:37450]->[10.96.214.17 as pytestserver.default:8083] size:0B svc=[default/go-deployment go] traceparent=[00-14f07e11b5e57f14fd2da0541f0ddc2f-319fb03373427a41[cfa6d5d448e40b00]-01]
2025-01-17 21:42:18.11794218 (5.284521ms[5.164701ms]) HTTP 200 GET /gotracemetoo [10.244.2.144 as nodejs-deployment.default:57814]->[10.244.1.92 as go-deployment.default:8080] size:0B svc=[default/go-deployment go] traceparent=[00-14f07e11b5e57f14fd2da0541f0ddc2f-cfa6d5d448e40b00[cce1e6b5e932b89a]-01]
2025-01-17 21:42:18.11794218 (1.934744ms[1.934744ms]) HTTP 403 GET /users [10.244.2.32 as python-deployment.default:46876]->[10.244.2.176 as rails-deployment.default:3040] size:222B svc=[default/rails-deployment ruby] traceparent=[00-14f07e11b5e57f14fd2da0541f0ddc2f-57d77d99e9665c54[3d97d26b0051112b]-01]
2025-01-17 21:42:18.11794218 (2.116628ms[2.116628ms]) HTTPClient 403 GET /users [10.244.2.32 as python-deployment.default:46876]->[10.96.69.89 as utestserver.default:3040] size:256B svc=[default/python-deployment python] traceparent=[00-14f07e11b5e57f14fd2da0541f0ddc2f-ff48ab147cc92f93[2770ac4619aa0042]-01]
2025-01-17 21:42:18.11794218 (4.281525ms[4.281525ms]) HTTP 200 GET /tracemetoo [10.244.1.92 as go-deployment.default:37450]->[10.244.2.32 as python-deployment.default:8083] size:178B svc=[default/python-deployment python] traceparent=[00-14f07e11b5e57f14fd2da0541f0ddc2f-2770ac4619aa0042[319fb03373427a41]-01]
2025-01-17 21:42:18.11794218 (5.391191ms[5.391191ms]) HTTPClient 200 GET /gotracemetoo [10.244.2.144 as nodejs-deployment.default:57814]->[10.96.134.167 as testserver.default:8080] size:256B svc=[default/nodejs-deployment nodejs] traceparent=[00-14f07e11b5e57f14fd2da0541f0ddc2f-202ee68205e4ef3b[9408610968fa20f8]-01]
2025-01-17 21:42:18.11794218 (6.939027ms[6.939027ms]) HTTP 200 GET /traceme [127.0.0.1 as 127.0.0.1:44720]->[127.0.0.1 as 127.0.0.1.default:3030] size:86B svc=[default/nodejs-deployment nodejs] traceparent=[00-14f07e11b5e57f14fd2da0541f0ddc2f-9408610968fa20f8[0000000000000000]-01]

```
