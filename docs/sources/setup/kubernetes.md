---
title: Deploy Beyla with Kubernetes manifests
menuTitle: Kubernetes manifests
description: Deploy Grafana Beyla in Kubernetes with your own manifests, as a DaemonSet that instruments the applications on each node or as a sidecar container that instruments one application, and send metrics and traces to an OpenTelemetry endpoint.
weight: 700
keywords:
  - Beyla
  - eBPF
  - Kubernetes
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/setup/kubernetes/
  - /docs/beyla/latest/tutorial/k8s-walkthrough/
---

# Deploy Beyla with Kubernetes manifests

You can deploy Grafana Beyla in Kubernetes with your own manifests instead of a Helm chart.
Use this option to create and manage all the Kubernetes resources that run Beyla yourself.

You can run Beyla in one of two ways:

- As a DaemonSet, which runs a Beyla Pod on your cluster nodes and instruments the applications on each node
- As a sidecar container, which runs Beyla in each Pod of one application and instruments only that Pod

To deploy Beyla with a Helm chart instead, refer to [Deploy Beyla with the Beyla Helm chart][beyla-helm].
To configure the Helm chart for Grafana Cloud Application Observability, refer to [Deploy Beyla with the Beyla Helm chart for Grafana Cloud][helm-cloud].
To deploy Beyla with Kubernetes cluster monitoring, refer to [Deploy Beyla with the Kubernetes Monitoring Helm chart][k8s-monitoring-helm].
To run Beyla inside Grafana Alloy, refer to [Deploy Beyla with the Grafana Alloy Helm chart][alloy-helm].

## Before you begin

Before you deploy Beyla, make sure you have the following:

- A Kubernetes cluster whose nodes meet the [Beyla requirements and limitations][requirements]
- `kubectl`, configured for the cluster
- Permission to create cluster-scoped resources and privileged Pods
- An OpenTelemetry Protocol (OTLP) endpoint for the Beyla metrics and traces, and the credentials for it, if any.
  For Grafana Cloud, follow the procedure in [Send data to the Grafana Cloud OTLP endpoint][cloud-otlp].
  For Grafana Alloy, refer to [Collect OpenTelemetry data and forward it to any OpenTelemetry-compatible endpoint][alloy-otlp].

## Pod requirements

Beyla loads eBPF programs into the node kernel, so its container needs elevated privileges.
Run the container in privileged mode, or grant only the Linux capabilities Beyla needs, as described in [Deploy Beyla unprivileged][unprivileged].

Beyla also needs to see the processes it instruments:

- In a DaemonSet, set `hostPID: true` in the Pod, so Beyla shares the process ID (PID) namespace of the node
- In a sidecar container, set `shareProcessNamespace: true` in the Pod, so Beyla shares the PID namespace of the other containers in the Pod

When Beyla runs in a Pod, it adds Kubernetes metadata, such as the namespace and Pod name, to metrics and traces.
To get the metadata, Beyla needs permission to list and watch Pods, Services, Nodes, and ReplicaSets in the Kubernetes API.
Beyla doesn't instrument a process in a container until it finds the Pod for that container, so without these permissions Beyla doesn't instrument containerized applications.

The default value of `BEYLA_KUBE_METADATA_ENABLE`, `autodetect`, turns on Kubernetes metadata when Beyla runs in Kubernetes.
To turn off Kubernetes metadata, set `BEYLA_KUBE_METADATA_ENABLE=false`, or set `attributes.kubernetes.enable: false` in the Beyla configuration file.
For the metadata attributes and options, refer to [Kubernetes decorator][k8s-decorator].

{{< admonition type="note" >}}
If the Beyla container doesn't have the capabilities it needs, Beyla logs a warning and keeps running, but it might malfunction.
To stop Beyla at startup instead, set `BEYLA_ENFORCE_SYS_CAPS=true`.
{{< /admonition >}}

## Create the service account and RBAC

Create a namespace for Beyla, and a service account with the permissions that Beyla needs to read Kubernetes metadata:

1. Create the `beyla` namespace:

   ```sh
   kubectl create namespace beyla
   ```

1. Save the following manifest as `beyla-rbac.yml`:

   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: beyla
     namespace: beyla
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
       resources: ["pods", "services", "nodes"]
       verbs: ["list", "watch"]
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

1. Create the resources:

   ```sh
   kubectl apply -f beyla-rbac.yml
   ```

## Create the Beyla configuration

Beyla reads its configuration from the file that `BEYLA_CONFIG_PATH` points to, and from environment variables.
Store the file in a ConfigMap, and store the OTLP credentials in a Secret:

1. Save the following ConfigMap as `beyla-config.yml`:

   ```yaml
   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: beyla-config
     namespace: beyla
   data:
     beyla-config.yml: |
       discovery:
         instrument:
           - k8s_namespace: <NAMESPACE>
   ```

   Replace _`<NAMESPACE>`_ with the namespace of the applications to instrument.
   Without a selector, Beyla exits at startup with a `missing application discovery section` error.
   Beyla still skips Kubernetes system namespaces and other services that it [excludes by default][default-exclude].
   For other ways to select applications, refer to [Configure Beyla service discovery][service-discovery].

1. Save the following Secret as `grafana-secret.yml`:

   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: grafana-secret
     namespace: beyla
   type: Opaque
   stringData:
     otlp-headers: "<OTLP_HEADERS>"
   ```

   Replace _`<OTLP_HEADERS>`_ with the headers your OTLP endpoint needs, such as authentication, as comma-separated `key=value` pairs.
   If your endpoint doesn't need headers, skip this step.

   For Grafana Cloud, copy the `OTEL_EXPORTER_OTLP_HEADERS` value that the **OpenTelemetry** tile of your stack generates.
   The value has the form `Authorization=Basic <BASE64_CREDENTIALS>`, where _`<BASE64_CREDENTIALS>`_ is your instance ID and token, joined by a colon and Base64-encoded.
   To create the credentials yourself, run `echo -n '<INSTANCE_ID>:<TOKEN>' | base64 | tr -d '\n'`.

1. Create the ConfigMap and the Secret:

   ```sh
   kubectl apply -f beyla-config.yml -f grafana-secret.yml
   ```

   If you skipped the Secret, apply only `beyla-config.yml`.

## Deploy Beyla as a DaemonSet

A DaemonSet runs a Beyla Pod on each node.
Each Pod instruments the applications on its node that match the `discovery` section of your configuration:

1. Save the following manifest as `beyla-daemonset.yml`:

   ```yaml
   apiVersion: apps/v1
   kind: DaemonSet
   metadata:
     name: beyla
     namespace: beyla
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
         serviceAccountName: beyla
         hostPID: true
         containers:
           - name: beyla
             image: grafana/beyla:latest
             securityContext:
               privileged: true
               readOnlyRootFilesystem: true
             env:
               - name: BEYLA_CONFIG_PATH
                 value: /config/beyla-config.yml
               - name: OTEL_EXPORTER_OTLP_ENDPOINT
                 value: "<OTLP_ENDPOINT>"
               - name: OTEL_EXPORTER_OTLP_HEADERS
                 valueFrom:
                   secretKeyRef:
                     name: grafana-secret
                     key: otlp-headers
             volumeMounts:
               - name: beyla-config
                 mountPath: /config
         volumes:
           - name: beyla-config
             configMap:
               name: beyla-config
   ```

   Replace _`<OTLP_ENDPOINT>`_ with the base URL of your OTLP endpoint.
   Beyla appends `/v1/metrics` and `/v1/traces`.
   For Grafana Cloud, copy the endpoint from the **OpenTelemetry** tile of your stack, for example `https://otlp-gateway-prod-eu-west-0.grafana.net/otlp`.

   For Grafana Alloy in the same cluster, use the Alloy Service and the HTTP port of the [`otelcol.receiver.otlp`][alloy-otlp-receiver] component.
   The default port is `4318`, for example `http://<ALLOY_SERVICE>.<ALLOY_NAMESPACE>:4318`.
   Replace _`<ALLOY_SERVICE>`_ and _`<ALLOY_NAMESPACE>`_ with the name and namespace of the Alloy Service.

   The `otelcol.receiver.otlp` component needs an `http` block, and the Alloy Service must expose the port.
   With the Alloy Helm chart, add the port to the `alloy.extraPorts` value.

   If you skipped the Secret, remove the `OTEL_EXPORTER_OTLP_HEADERS` variable.

   The DaemonSet skips nodes with taints that it doesn't tolerate, such as control-plane nodes.
   To run Beyla on every node, add the following `tolerations` to the Pod spec, at the same level as `containers`:

   ```yaml
   tolerations:
     - effect: NoSchedule
       operator: Exists
     - effect: NoExecute
       operator: Exists
   ```

1. Create the DaemonSet:

   ```sh
   kubectl apply -f beyla-daemonset.yml
   ```

With this configuration, Beyla does the following:

- Instruments applications in the _`<NAMESPACE>`_ namespace, except services that Beyla [excludes by default][default-exclude]
- Adds Kubernetes metadata attributes, for example `k8s.namespace.name` and `k8s.pod.name`
- Exports application metrics and traces to your OTLP endpoint
- Doesn't export [network-level metrics][network] or Prometheus metrics

To also expose Prometheus metrics, or to use them instead of OTLP, refer to [Configure Beyla Prometheus and OpenTelemetry data export][export-data].

## Check that Beyla is running

To check the deployment, complete the following steps:

1. Check that the Beyla Pods are running:

   ```sh
   kubectl get pods --namespace beyla
   ```

1. Check the logs of a Beyla Pod:

   ```sh
   kubectl logs --namespace beyla <POD_NAME>
   ```

   Replace _`<POD_NAME>`_ with a Pod name from the previous command.
   The log includes a `Grafana Beyla` line that shows the Beyla version.
   If the log shows `Required system capabilities not present, Beyla may malfunction`, grant the capabilities that the message lists.

1. (Optional) To see each request that Beyla instruments, add the following variable to the `env` list of the Beyla container in `beyla-daemonset.yml`:

   ```yaml
   - name: BEYLA_TRACE_PRINTER
     value: text
   ```

   Then run `kubectl apply -f beyla-daemonset.yml` again.
   After the applications receive requests, the Beyla log shows one line for each request.
   Remove the variable when you finish testing.

After the instrumented applications receive requests, their metrics and traces appear in your OTLP backend.

## Deploy Beyla as a sidecar container

To instrument only the Pods of one application, run Beyla as a sidecar container in the Pod template of that application:

1. If the application runs in a namespace other than `beyla`, prepare that namespace:
   - Create a `beyla` service account in the namespace, and add it to the `subjects` of the `beyla` ClusterRoleBinding
   - Create the `grafana-secret` Secret in the namespace

   A Pod can only reference Secrets in its own namespace.

1. Add the following to the Pod template of the application, for example in its Deployment:

   ```yaml
   spec:
     template:
       spec:
         shareProcessNamespace: true
         serviceAccountName: beyla
         containers:
           # Keep the existing application containers, and add:
           - name: beyla
             image: grafana/beyla:latest
             securityContext:
               privileged: true
             env:
               - name: BEYLA_OPEN_PORT
                 value: "<SERVICE_PORT>"
               - name: OTEL_EXPORTER_OTLP_ENDPOINT
                 value: "<OTLP_ENDPOINT>"
               - name: OTEL_EXPORTER_OTLP_HEADERS
                 valueFrom:
                   secretKeyRef:
                     name: grafana-secret
                     key: otlp-headers
                     optional: true
   ```

   Replace the following:

   - _`<SERVICE_PORT>`_: The port the application opens inside its container
   - _`<OTLP_ENDPOINT>`_: The base URL of your OTLP endpoint

   Beyla still skips Kubernetes system namespaces and other services that it [excludes by default][default-exclude].

   The `serviceAccountName` value replaces the service account of the application.
   If the application needs its own service account, keep its `serviceAccountName` and remove `serviceAccountName: beyla` from the snippet.
   Then add the service account of the application to the `subjects` of the `beyla` ClusterRoleBinding.

1. Apply the updated manifest of the application, for example:

   ```sh
   kubectl apply -f <APPLICATION_MANIFEST>
   ```

   Replace _`<APPLICATION_MANIFEST>`_ with the file that contains the application Deployment.

1. Check the logs of the Beyla container in one of the application Pods:

   ```sh
   kubectl logs --namespace <APP_NAMESPACE> <POD_NAME> --container beyla
   ```

   Replace _`<APP_NAMESPACE>`_ with the namespace of the application, and _`<POD_NAME>`_ with the name of one of its Pods.

## Turn on network-level context propagation

Beyla can propagate trace context at network level, by adding it to outgoing requests.
Network-level context propagation is off by default.
For how it works, refer to [Context propagation at network level][context-propagation].

To turn on network-level context propagation in the DaemonSet, complete the following steps:

1. In `beyla-config.yml`, add the `ebpf.context_propagation` option to the Beyla configuration:

   ```yaml
   data:
     beyla-config.yml: |
       discovery:
         instrument:
           - k8s_namespace: <NAMESPACE>
       ebpf:
         context_propagation: all
   ```

   HTTP header propagation needs Linux kernel 5.17 or later.
   For the other values, refer to [Distributed traces with Beyla][traces].

1. In `beyla-daemonset.yml`, give the Pod host network access, and mount the `/sys/fs/cgroup` and `/sys/kernel/tracing` directories of the node.
   Add the following entries to the Pod spec, and keep the `beyla-config` entries:

   ```yaml
   spec:
     template:
       spec:
         hostNetwork: true
         dnsPolicy: ClusterFirstWithHostNet
         containers:
           - name: beyla
             volumeMounts:
               - name: cgroup     # Track new sockets to propagate context
                 mountPath: /sys/fs/cgroup
               - name: tracefs    # Mitigate the FIONREAD kernel bug
                 mountPath: /sys/kernel/tracing
         volumes:
           - name: cgroup
             hostPath:
               path: /sys/fs/cgroup
           - name: tracefs
             hostPath:
               path: /sys/kernel/tracing
   ```

   The `ClusterFirstWithHostNet` DNS policy lets the Pod resolve cluster DNS names, such as the name of an Alloy Service, while it uses the host network.

1. If you run Beyla unprivileged, add `NET_ADMIN` to the capabilities of the Beyla container.

1. Apply both files:

   ```sh
   kubectl apply -f beyla-config.yml -f beyla-daemonset.yml
   ```

## Deploy Beyla unprivileged

Instead of a privileged container, you can run Beyla with only the Linux capabilities it needs.
Whether this works depends on your Kubernetes version and container runtime, for example containerd, CRI-O, or Docker.
These steps were tested mainly with containerd on GKE, `kubeadm`, k3s, MicroK8s, and kind.
For what each capability does, refer to [Beyla security, permissions, and capabilities][security].

To run Beyla unprivileged, complete the following steps:

1. In the Beyla container of your DaemonSet or sidecar, replace the `securityContext` section with the following:

   ```yaml
   securityContext:
     runAsUser: 0
     readOnlyRootFilesystem: true
     capabilities:
       add:
         - BPF                # Required for most eBPF probes
         - SYS_PTRACE         # Access the container namespaces and inspect executables
         - NET_RAW            # Use socket filters for HTTP requests
         - CHECKPOINT_RESTORE # Open the libraries of instrumented processes through /proc/<pid>/map_files
         - DAC_READ_SEARCH    # Open ELF files
         - PERFMON            # Load BPF programs
         # - SYS_RESOURCE     # Kernels earlier than 5.11 only: increase the locked memory limit
         - SYS_ADMIN          # Go context propagation, trace-log correlation, or kernel.perf_event_paranoid above 2
       drop:
         - ALL
   ```

   Some Debian-based distributions set `kernel.perf_event_paranoid` higher than `2`.
   On those nodes, Beyla needs `SYS_ADMIN`, or you can lower the setting to `2`.
   For details, refer to [Performance monitoring tasks][perf-tasks].
   If you turn on [network-level context propagation][context-propagation-task], also add `NET_ADMIN`.

1. Apply the updated manifest, for example:

   ```sh
   kubectl apply -f beyla-daemonset.yml
   ```

### Deploy unprivileged Beyla on OpenShift

The default OpenShift Security Context Constraint (SCC) policy doesn't allow the host access, user ID, and Linux capabilities that unprivileged Beyla needs.
A cluster administrator can create a dedicated SCC that permits these settings without allowing privileged containers:

1. Save the following SCC as `beyla-scc.yml`:

   ```yaml
   apiVersion: security.openshift.io/v1
   kind: SecurityContextConstraints
   metadata:
     name: beyla
   allowHostDirVolumePlugin: true
   allowHostNetwork: true
   allowHostPID: true
   allowHostPorts: true
   allowPrivilegedContainer: false
   allowedCapabilities:
     - BPF
     - SYS_PTRACE
     - NET_RAW
     - CHECKPOINT_RESTORE
     - DAC_READ_SEARCH
     - PERFMON
     - SYS_ADMIN
     - NET_ADMIN
   readOnlyRootFilesystem: true
   runAsUser:
     type: MustRunAs
     uid: 0
   seLinuxContext:
     type: RunAsAny
   fsGroup:
     type: RunAsAny
   supplementalGroups:
     type: RunAsAny
   ```

   The SCC also allows host networking, host ports, and the `NET_ADMIN` capability.
   If you don't turn on network-level context propagation, you can remove `allowHostNetwork`, `allowHostPorts`, and `NET_ADMIN`.

1. Create the SCC, and grant it only to the `beyla` service account:

   ```sh
   oc apply -f beyla-scc.yml
   oc adm policy add-scc-to-user beyla -z beyla -n beyla
   ```

   For a sidecar, run the `oc adm policy` command again with `-z <APP_SERVICE_ACCOUNT> -n <APP_NAMESPACE>`, where _`<APP_SERVICE_ACCOUNT>`_ is the service account used by the application Pod and _`<APP_NAMESPACE>`_ is its namespace.
   The SCC applies to every container in the Pod, so the application containers also run as user `0` with a read-only root file system.

1. Keep the capability-based `securityContext` from the previous section.
   The SCC permits those settings but keeps `allowPrivilegedContainer` disabled.

SCC assignments grant elevated permissions.
Use a dedicated namespace and service account for Beyla, and review the SCC with your OpenShift administrator before you deploy it in production.

## Next steps

- [Configure Beyla][configure]
- [Configure Beyla service discovery][service-discovery]
- [Configure Beyla Prometheus and OpenTelemetry data export][export-data]
- [Beyla security, permissions, and capabilities][security]
- [Distributed traces with Beyla][traces]

[alloy-helm]: ../helm-alloy/
[alloy-otlp]: https://grafana.com/docs/alloy/latest/collect/opentelemetry-data/
[alloy-otlp-receiver]: https://grafana.com/docs/alloy/latest/reference/components/otelcol/otelcol.receiver.otlp/
[beyla-helm]: ../kubernetes-helm/
[cloud-otlp]: https://grafana.com/docs/grafana-cloud/send-data/otlp/send-data-otlp/#manual-opentelemetry-setup-for-advanced-users
[configure]: ../../configure/
[context-propagation]: ../../traces/#context-propagation-at-network-level
[context-propagation-task]: #turn-on-network-level-context-propagation
[default-exclude]: ../../configure/service-discovery/#default-exclude-services-from-instrumentation
[export-data]: ../../configure/export-data/
[helm-cloud]: ../kubernetes-helm-appolly/
[k8s-decorator]: ../../configure/metrics-traces-attributes/#kubernetes-decorator
[k8s-monitoring-helm]: ../kubernetes-helm-k8s-monitoring/
[network]: ../../network/
[perf-tasks]: ../security/#performance-monitoring-tasks
[requirements]: ../../introduction/requirements/
[security]: ../security/
[service-discovery]: ../../configure/service-discovery/
[traces]: ../../traces/
[unprivileged]: #deploy-beyla-unprivileged
