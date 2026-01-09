---
title: Configure Beyla instrumentation options
menuTitle: Controlling instrumentation
description: Configure the way instrumentation behaves for various protocols and programming languages
weight: 32
keywords:
  - Beyla
  - eBPF
---

# Configure Beyla instrumentation options

This configuration section describes various options for controlling the instrumentation capabilities of Beyla related to distributed traces, context propagation and various protocol instrumentation options.

## Distributed traces and context propagation

YAML section: `ebpf`

You can configure the component under the `ebpf` section of your YAML configuration or via environment variables.

| YAML<p>environment variable</p>                                           | Description                                                                                                                                                                      | Type    | Default  |
| ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | -------- |
| `enable_context_propagation`<p>`BEYLA_BPF_ENABLE_CONTEXT_PROPAGATION`</p> | Deprecated. Use `context_propagation` instead. For more information, refer to the [enable context propagation section](#enable-context-propagation).                             | boolean | false    |
| `context_propagation`<p>`BEYLA_BPF_CONTEXT_PROPAGATION`</p>               | Controls trace context propagation method. Accepted: `all`, `headers`, `ip`, `disabled`. For more information, refer to the [context propagation section](#context-propagation). | string  | disabled |
| `track_request_headers`<p>`BEYLA_BPF_TRACK_REQUEST_HEADERS`</p>           | Track incoming `Traceparent` headers for trace spans. For more information, refer to the [track request headers section](#track-request-headers).                                | boolean | false    |

### Enable context propagation

Deprecated. Use `context_propagation` instead.

### Context propagation

Beyla injects the `Traceparent` header value for outgoing HTTP requests, so it can propagate any incoming context to downstream services. This context propagation works for any programming language.

For TLS encrypted HTTP requests (HTTPS), Beyla encodes the `Traceparent` header value at the TCP/IP packet level. Beyla must be present on both sides of the communication.

The TCP/IP packet level encoding uses Linux Traffic Control (TC). eBPF programs that also use TC must chain correctly with Beyla. For more information about chaining programs, see the [Cilium compatibility documentation](../../cilium-compatibility/).

You can disable the TCP/IP level encoding and TC programs by setting `context_propagation="headers"`. This context propagation is fully compatible with any OpenTelemetry distributed tracing library.

Context propagation values:

- `all`: Enable both HTTP and IP options context propagation
- `headers`: Enable context propagation via the HTTP headers only
- `ip`: Enable context propagation via the IP options field only
- `disabled`: Disable trace context propagation

To use this option in containerized environments (Kubernetes and Docker), you must:

- Deploy Beyla as a `DaemonSet` with host network access `hostNetwork: true`
- Volume mount the `/sys/fs/cgroup` path from the host as local `/sys/fs/cgroup` path
- Grant the `CAP_NET_ADMIN` capability to the Beyla container

gRPC and HTTP2 are not supported.

For an example of how to configure distributed traces in Kubernetes, see our [Distributed traces with Beyla](../../distributed-traces/) guide.

### Track request headers

This option lets Beyla process any incoming `Traceparent` header values. If enabled, when Beyla sees an incoming server request with a `Traceparent` header value, it uses the provided 'trace id' to create its own trace spans.

This option does not affect Go applications, where the `Traceparent` field is always processed.

Enabling this option may increase performance overhead in high request volume scenarios. This option is only useful when generating Beyla traces; it does not affect metrics.

## Payload extraction

Various cloud and database protocols are implemented on top of HTTP. For example, all AWS S3 (Amazon Web Services) requests are in fact HTTP requests. To create better traces and metrics, Beyla has custom protocol detectors which run on top of HTTP, by performing HTTP payload extraction. You can configure which payload extractors are enabled by default with the following options:

YAML section:

```
ebpf:
  http:
    graphql:
```

| YAML option<p>Environment variable</p>                    | Description                                                   | Type    | Default |
| --------------------------------------------------------- | ------------------------------------------------------------- | ------- | ------- |
| `enabled`<p>`BEYLA_HTTP_GRAPHQL_ENABLED`</p>              | Enable GraphQL protocol detection in HTTP payload processing. | boolean | (true)  |

YAML section:

```
ebpf:
  http:
    elasticsearch:
```

| YAML option<p>Environment variable</p>                    | Description                                                         | Type    | Default |
| --------------------------------------------------------- | ------------------------------------------------------------------- | ------- | ------- |
| `enabled`<p>`BEYLA_HTTP_HTTP_ELASTICSEARCH_ENABLED`</p>   | Enable Elasticsearch protocol detection in HTTP payload processing. See below for details. | boolean | (true)  |

`Opensearch` is a fork of `Elasticsearch` and therefore also supported.

| Product             | Methods                                                                                  | Version  |
| --------------------| ---------------------------------------------------------------------------------------- | -------- |
| `Elasticsearch`     | /_search, /_msearch, /_bulk, /_doc                                                       | 7.14+    |
| `Opensearch`        | /_search, /_msearch, /_bulk, /_doc                                                       | 3.0.0+   |


YAML section:

```
ebpf:
  http:
    aws:
```

| YAML option<p>Environment variable</p>          | Description                                                        | Type    | Default |
| ----------------------------------------------- | ------------------------------------------------------------------ | ------- | ------- |
| `enabled`<p>`BEYLA_HTTP_HTTP_AWS_ENABLED`</p>   | Enable AWS services protocol detection in HTTP payload processing. See below for list of AWS supported protocols. | boolean | (true)  |

List of supported AWS services protocol detectors:

| Protocol          | Methods                                                                                  |
| ------------------| ---------------------------------------------------------------------------------------- |
| S3                | CreateBucket, DeleteBucket, PutObject, DeleteObject, ListBuckets, ListObjects, GetObject |
| SQS               | All                                                                                      |

## Configure data processing buffer sizes

To minimize the performance impact of eBPF data collection, Beyla uses limited payload buffer size capture for various protocols, which gives us the best quality to performance ratio. However, for certain kinds of protocols, especially for some that are mentioned in [Payload extraction](#payload-extraction), it might be beneficial to use larger buffer sizes. The following section describes the configuration options for controlling the auxiliary buffers captured for higher quality trace generation.

YAML section:

```
ebpf:
  buffer_sizes:
```

| YAML option<p>Environment variable</p>            | Description                                                         | Type    | Default | Maximum |
| ------------------------------------------------- | ------------------------------------------------------------------- | ------- | ------- | ------- |
| `http`<p>`BEYLA_BPF_BUFFER_SIZE_HTTP`</p>         | Auxiliary buffer size (in bytes) for HTTP protocol capture.         | int     | (0)     | 8192    |
| `mysql`<p>`BEYLA_BPF_BUFFER_SIZE_MYSQL`</p>       | Auxiliary buffer size (in bytes) for MYSQL protocol capture.        | int     | (0)     | 8192    |
| `postgres`<p>`BEYLA_BPF_BUFFER_SIZE_POSTGRES`</p> | Auxiliary buffer size (in bytes) for POSTGRESQL protocol capture.   | int     | (0)     | 8192    |

## Other attributes

YAML section: `ebpf`

| YAML option<p>Environment variable</p>                    | Description                                                   | Type    | Default |
| --------------------------------------------------------- | ------------------------------------------------------------- | ------- | ------- |
| `heuristic_sql_detect`<p>`BEYLA_HEURISTIC_SQL_DETECT`</p> | Enable heuristic SQL client detection. See below for details. | boolean | (false) |

The `heuristic sql detect` option lets Beyla detect SQL client requests by inspecting query statements, even if the protocol is not directly supported. By default, Beyla detects SQL client requests by their binary protocol format. If you use a database technology not directly supported by Beyla, you can enable this option to get database client telemetry. This option is not enabled by default, because it can create false positives, for example, if an application sends SQL text for logging through a TCP connection. Currently, Beyla natively supports the Postgres and MySQL binary protocols.

| YAML option<p>Environment variable</p>                        | Description                                                   | Type    | Default |
| ------------------------------------------------------------- | ------------------------------------------------------------- | ------- | ------- |
| `max_transaction_time`<p>`BEYLA_BPF_MAX_TRANSACTION_TIME`</p> | Maximum allowed transaction time. See below for details.      | string  | (5m)    |

The `max_transaction_time` option configures the distributed tracing transaction correlation maximum allowed time. It specifies the maximum time allowed for two requests to be correlated as parent -> child.
This is implemented as a safety measure for limiting the maximum possible trace size, because some programs (for example load generators) keep on generating requests from the same thread in perpetuity, which can generate very large traces. 
If a child request has started later than the time specified by `max_transaction_time`, then we consider the two requests not correlated to prevent infinite traces.
