# Beyla Troubleshooting guide

For more accurate troubleshooting, Beyla should run with the `BEYLA_LOG_LEVEL` property set to `debug` and the 
`BEYLA_TRACE_PRINTER` property set to `text`.

## Beyla crashes after start

Example message:
```
time=2025-02-06T10:49:50.406+01:00 level=ERROR msg="Beyla ran with errors" error="can't find target process: couldn't start Process Finder: can't instantiate discovery.ProcessFinder pipeline: invoking Final node provider: error invoking provider: removing memory lock: failed to set memlock rlimit: operation not permitted"
```

This indicates that Beyla is trying to lock memory but the process doesn't have the necessary permissions. Read [Beyla security, permissions, and capabilities](https://github.com/grafana/beyla/blob/main/docs/sources/security.md) to understand the necessary permissions.

## Beyla starts but is not displaying any traces/metrics

### Check that the process is properly selected

If even running Beyla with `BEYLA_TRACE_PRINTER=text`, you don't see any trace in the logs,
check that Beyla is finding any process to instrument. The logs should show a message like:

```
level=INFO msg="instrumenting process" component=discover.TraceAttacher cmd=/frontend pid=1
```

If you don't see any message like the preceding, make sure that the process is properly selected, either with the
`BEYLA_EXECUTABLE_NAME`, `BEYLA_OPEN_PORT` or with the [discovery YAML section](https://github.com/grafana/beyla/blob/main/docs/sources/configure/options.md#global-configuration-properties).

If you still don't see any message like the preceding, check [Deploy Beyla in Kubernetes](https://github.com/grafana/beyla/blob/main/docs/sources/setup/kubernetes.md) to see if the process is properly selected.

If the logs show a message like the preceding, but you don't see printed traces, make sure that the
instrumented service has traffic.

If you see printed traces, but you don't see metrics in Grafana, go to [Check connectivity issues](#check-connectivity-issues).

> ⚠️Grafana AppO11y often takes up to 5 minutes to start visualizing traces. First search for metrics
> or traces in the Grafana Explorer.

### Check connectivity issues

If Beyla is configured to export metrics as Prometheus metrics.
* Make sure that the `BEYLA_PROMETHEUS_PORT` configuration option is set.
* Check the value of the `BEYLA_PROMETHEUS_PATH` configuration option. If it
  is not set, the `/metrics` path is assumed.
* Run `curl` against the Beyla Prometheus endpoint.
  1. If you see metrics, the problem is in the Prometheus collector.
  2. If you don't see metrics, report the bug.

If Beyla is configured to export metrics and/or traces to Grafana Cloud (OTEL endpoint):
* Check the correct values of the `GRAFANA_CLOUD_ZONE`, `GRAFANA_CLOUD_INSTANCE_ID`
  and `GRAFANA_CLOUD_API_KEY` values.
* Consider that the `GRAFANA_CLOUD_SUBMIT` variable is defaulted to `traces`.
  If you want to send metrics, you should send it to `metrics` or `traces,metrics`.
  * If using the YAML configuration instead of environment variables, consider
    that the value is not a string but an array of strings.
* If everything is correct and you don't see error messages, you might need to debug
  the OpenTelemetry SDK. Set the `BEYLA_OTEL_SDK_LOG_LEVEL=debug` variable.

> ⚠️Please consider that Grafana AppO11y requires submission of traces. If you are
> sending metrics, your data should be visible in Grafana but not in the AppO11y plugin.

If Beyla is configured to export metrics and/or traces to any other OpenTelemetry
collector:
* Beyla accepts the standard [OpenTelemetry exporter configuration](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/)
  variables.
* If everything is correct and you don't see error messages, you might need to debug
  the OpenTelemetry SDK. Set the `BEYLA_OTEL_SDK_LOG_LEVEL=debug` variable.
* If everything is still correct, the problem might be in the collector side.


## Kubernetes metadata decoration not working

If your Beyla logs are full of messages like the following one:
```
W1123 10:20:26.347945    2078 reflector.go:533] k8s.io/client-go/informers/factory.go:150:
 failed to list *v1.Pod: pods is forbidden: User "system:serviceaccount:default:beyla"
 cannot list resource "pods" in API group "" at the cluster scope
``` 

This means that you need to give Kubernetes permission to the Beyla Pod.

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

And then add the `serviceAccountName: beyla` property to the Beyla pod.

## Beyla consuming too many resources (CPU or Memory)

### How to profile

To help diagnosing any performance bottleneck, you might want to ask users to create and send us a
CPU/memory profile. Read [Beyla profiling guide](https://github.com/grafana/beyla/blob/main/devdocs/profiling.md) to understand how to profile Beyla.

### Which features to disable to improve performance

Even if Beyla works at its expected performance, it might consume too many resources in highly
overloaded scenarios. At this point, the user might want to trade off some features for performance.

Take a look at [Beyla performance overhead](https://github.com/grafana/beyla/blob/main/docs/sources/performance.md) to understand the overhead of each feature. Some other things that can be done to improve performance are:

* [Sample traces to decrease traffic](https://github.com/grafana/beyla/blob/main/docs/sources/configure/sample-traces.md)
* Set the `BEYLA_BPF_WAKEUP_LEN` variable. This will cause that the Beyla user-space process doesn't
  have to wake-up every time the kernel side sends a message.
  * In high-load services (in terms of requests/second), tuning this option values can help with reducing the CPU
    overhead of Beyla.
  * In low-load services (in terms of requests/second), high values of `wakeup_len` could add a noticeable delay in
    the period the metrics are submitted and become externally visible.
* Set `BEYLA_KUBE_METADATA_ENABLE` to `false` to disable decoration of Kubernetes attributes.
* In the `routes` section of the YAML file, set the `unmatched` property to `wildcard`
  and remove any other section (`patterns`, `ignored_patterns`, `ignore_mode`).