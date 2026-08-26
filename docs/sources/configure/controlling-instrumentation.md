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
| `context_propagation`<p>`BEYLA_BPF_CONTEXT_PROPAGATION`</p>               | Controls trace context propagation. Accepted values are `headers`, `tcp`, `headers,tcp`, `all`, and `disabled`. For more information, refer to the [context propagation section](#context-propagation). | string  | disabled |
| `track_request_headers`<p>`BEYLA_BPF_TRACK_REQUEST_HEADERS`</p>           | Track incoming `Traceparent` headers for trace spans. For more information, refer to the [track request headers section](#track-request-headers).                                | boolean | false    |

### Enable context propagation

Deprecated. Use `context_propagation` instead.

### Context propagation

Beyla can inject trace context into HTTP headers, TCP options, or both. Configure one of the following values:

- `headers`: Inject W3C `traceparent` headers. This interoperates with services instrumented by OpenTelemetry SDKs.
- `tcp`: Inject context into TCP option kind 25. Beyla must instrument both endpoints.
- `headers,tcp`: Enable both mechanisms. Incoming HTTP headers take precedence when both mechanisms provide context.
- `all`: Enable both mechanisms. This is equivalent to `headers,tcp`.
- `disabled`: Disable trace context propagation. This is the default.

For example, enable both mechanisms in the YAML configuration:

```yaml
ebpf:
  context_propagation: headers,tcp
```

To enable only HTTP header propagation with an environment variable:

```shell
export BEYLA_BPF_CONTEXT_PROPAGATION=headers
```

TCP propagation can carry context for encrypted HTTP/1 traffic because it does not modify the encrypted payload. It does not cross proxies or load balancers that terminate and create new TCP connections. TCP options are not used for HTTP/2 or gRPC because one connection can carry concurrent streams with different trace contexts.

To use this option in containerized environments (Kubernetes and Docker), you must:

- Deploy Beyla as a `DaemonSet` with host network access `hostNetwork: true`
- Volume mount the `/sys/fs/cgroup` path from the host as local `/sys/fs/cgroup` path
- The `/sys/kernel/tracing` path from the host must be volume mounted as local `/sys/kernel/tracing` path, because of the
  mitigation code added to handle the [FIONREAD kernel bug](https://lore.kernel.org/bpf/CAOvpEWN6xgFx4GWFnnWLGCB+_1auDcAZPYPSv1PDu3UfXkcriw@mail.gmail.com/t/#r36b3618483204331fed2978fbaa67be0cb6ad975).
- Grant the `CAP_NET_ADMIN` capability to the Beyla container

For more information about protocol support and limitations, including a Kubernetes configuration example, refer to [Distributed traces with Beyla](../../distributed-traces/).

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

### Generative AI instrumentation

Beyla can identify supported GenAI providers and higher-level GenAI operations by inspecting HTTP payloads. Each detector is disabled by default and can be enabled independently.

YAML section:

```yaml
ebpf:
  payload_extraction:
    http:
      genai:
```

| YAML option<p>Environment variable</p>                                   | Description                                                                                      | Type    | Default |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------ | ------- | ------- |
| `openai.enabled`<p>`BEYLA_HTTP_OPENAI_ENABLED`</p>                       | Enable OpenAI payload extraction and parsing.                                                    | boolean | false   |
| `anthropic.enabled`<p>`BEYLA_HTTP_ANTHROPIC_ENABLED`</p>                 | Enable Anthropic payload extraction and parsing.                                                 | boolean | false   |
| `gemini.enabled`<p>`BEYLA_HTTP_GEMINI_ENABLED`</p>                       | Enable Google AI Studio (Gemini) payload extraction and parsing.                                 | boolean | false   |
| `qwen.enabled`<p>`BEYLA_HTTP_QWEN_ENABLED`</p>                           | Enable `Qwen` (`DashScope`) payload extraction and parsing.                                      | boolean | false   |
| `bedrock.enabled`<p>`BEYLA_HTTP_BEDROCK_ENABLED`</p>                     | Enable AWS Bedrock payload extraction and parsing.                                               | boolean | false   |
| `mcp.enabled`<p>`BEYLA_HTTP_MCP_ENABLED`</p>                             | Enable Model Context Protocol (MCP) payload extraction and parsing.                              | boolean | false   |
| `embedding.enabled`<p>`BEYLA_HTTP_GENAI_EMBEDDING_ENABLED`</p>           | Enable generic embedding provider (`Voyage AI`, `Cohere`, `Jina AI`) payload extraction and parsing. | boolean | false   |
| `rerank.enabled`<p>`BEYLA_HTTP_RERANK_ENABLED`</p>                       | Enable `rerank` (`Cohere`, `Jina AI`, `Voyage AI`, etc.) payload extraction and parsing.          | boolean | false   |
| `retrieval.enabled`<p>`BEYLA_HTTP_RETRIEVAL_ENABLED`</p>                 | Enable vector retrieval (`Pinecone`, `Qdrant`, `Milvus`, `Chroma`, `Weaviate`, etc.) payload extraction and parsing. | boolean | false   |
| `ollama.enabled`<p>`BEYLA_HTTP_OLLAMA_ENABLED`</p>                       | Enable the `Ollama` native API payload extraction and parsing.                                   | boolean | false   |
| `openai_compatible.enabled`<p>`BEYLA_HTTP_OPENAI_COMPATIBLE_ENABLED`</p> | Enable payload extraction and parsing for configured OpenAI-compatible gateways.                 | boolean | false   |
| `openai_compatible.gateways`                                             | Configure gateway destinations. Each entry requires `host` and can include `port` and `provider`. | list    | empty   |

For example, enable OpenAI and embedding detection and configure an OpenAI-compatible gateway:

```yaml
ebpf:
  payload_extraction:
    http:
      genai:
        openai:
          enabled: true
        embedding:
          enabled: true
        openai_compatible:
          enabled: true
          gateways:
            - host: llm-gateway.example.com
              port: 443
              provider: acme-gateway
```

The `host` match is case-insensitive. If `port` is omitted, Beyla matches any destination port. The optional `provider` value is reported in the `gen_ai.provider.name` span attribute.

### HTTP header extraction

Beyla can extract selected HTTP request and response headers and add them as span attributes, and can obfuscate selected header values before export. To enable this feature, configure HTTP payload enrichment, select the header attributes for export, and set an HTTP buffer size large enough to capture the headers you want to inspect. Header extraction is disabled by default to avoid leaking sensitive data and increasing trace cardinality.

Extracted request headers are exported as `http.request.header.<header_name>` span attributes. Extracted response headers are exported as `http.response.header.<header_name>` span attributes. Header names are converted to lowercase in the exported attribute name, and header values are exported as string arrays. This configuration adds attributes to traces; it does not add HTTP headers as Beyla RED metric labels.

YAML section:

```yaml
ebpf:
  payload_extraction:
    http:
      enrichment:
```

| YAML option<p>Environment variable</p>                                                                  | Description                                                                                   | Type    | Default |
| ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------- | ------- |
| `enabled`<p>`BEYLA_HTTP_ENRICHMENT_ENABLED`</p>                                                        | Enable HTTP header and body enrichment.                                                       | boolean | false   |
| `policy.default_action.headers`                                                                         | Default action for HTTP headers that do not match a rule. Accepted values: `exclude`, `include`, `obfuscate`. | string  | exclude |
| `policy.default_action.body`                                                                            | Default action for HTTP body content that does not match a rule. Accepted values: `exclude`, `include`, `obfuscate`. | string  | exclude |
| `policy.obfuscation_string`<p>`BEYLA_HTTP_ENRICHMENT_OBFUSCATION_STRING`</p>                           | Replacement string used when a rule action is `obfuscate`.                                    | string  | `***`   |
| `rules`                                                                                                 | Ordered list of include, exclude, and obfuscate rules.                                        | list    | empty   |

For example, this configuration extracts `X-Tenant-ID`, `X-Forwarded-Host`, and response rate-limit headers, and shows how to obfuscate request `Authorization` values before export:

```yaml
attributes:
  select:
    traces:
      include:
        - "http.request.header.*"
        - "http.response.header.*"

ebpf:
  buffer_sizes:
    http: 8192
  payload_extraction:
    http:
      enrichment:
        enabled: true
        policy:
          default_action:
            headers: exclude
            body: exclude
          obfuscation_string: "***"
        rules:
          - action: obfuscate
            type: headers
            scope: request
            match:
              patterns:
                - "Authorization"
              case_sensitive: false
          - action: include
            type: headers
            scope: all
            match:
              patterns:
                - "X-Tenant-ID"
                - "X-Forwarded-Host"
                - "X-RateLimit-*"
              case_sensitive: false
```

With this configuration, Beyla can add attributes such as `http.request.header.x-tenant-id`, `http.request.header.x-forwarded-host`, and `http.response.header.x-ratelimit-remaining` to spans.

HTTP header enrichment is currently not available for Go applications.

Header rules use the following fields:

- `action`: `include`, `exclude`, or `obfuscate`.
- `type`: Set to `headers` for header extraction rules.
- `scope`: `request`, `response`, or `all`.
- `match.patterns`: Header name glob patterns.
- `match.case_sensitive`: Whether the header name match is case-sensitive.
- `match.url_path_patterns`: Optional URL path glob patterns for limiting where the rule applies.
- `match.methods`: Optional list of HTTP methods for limiting where the rule applies.
- `match.response_status_code`: Optional response status code comparisons for
  limiting where the rule applies. Supported comparisons are `equals`,
  `not_equals`, `greater_than`, `greater_equals`, `less_than`, and `less_equals`.
- `obfuscation_string`: Optional replacement string used when the rule action
  is `obfuscate`. It overrides `policy.obfuscation_string` for that rule.

Header rules are evaluated in order, and the first matching header rule wins. Put specific obfuscation or exclusion rules before broader include rules. Avoid setting `policy.default_action.headers: include` unless you have reviewed the data, because it can expose credentials, cookies, or user-identifying values and can add high-cardinality span attributes.

When a rule specifies multiple response status code comparisons, all of them
must match. For example, the following rule includes response headers only for
4xx responses other than 404:

```yaml
ebpf:
  payload_extraction:
    http:
      enrichment:
        enabled: true
        rules:
          - action: include
            type: headers
            scope: response
            match:
              patterns: ["*"]
              response_status_code:
                greater_equals: 400
                less_than: 500
                not_equals: 404
```

Body obfuscation rules use `match.obfuscation_json_paths` to select fields in
JSON request or response bodies. This field only applies to body rules with the
`obfuscate` action. All matching body rules are combined, and each rule can use
its own `obfuscation_string`; when omitted, the rule uses
`policy.obfuscation_string`.

```yaml
ebpf:
  payload_extraction:
    http:
      enrichment:
        enabled: true
        policy:
          default_action:
            headers: exclude
            body: exclude
          obfuscation_string: "***"
        rules:
          - action: obfuscate
            type: body
            scope: response
            obfuscation_string: "PII"
            match:
              response_status_code:
                greater_equals: 200
                less_than: 300
              obfuscation_json_paths:
                - "$.user.email"
                - "$.user.ssn"
```

## Configure data processing buffer sizes

To minimize the performance impact of eBPF data collection, Beyla uses limited payload buffer size capture for various protocols, which gives us the best quality to performance ratio. However, for certain kinds of protocols, especially for some that are mentioned in [Payload extraction](#payload-extraction), it might be beneficial to use larger buffer sizes. HTTP header extraction also requires an HTTP buffer size large enough to include the headers in the captured request or response. The following section describes the configuration options for controlling the auxiliary buffers captured for higher quality trace generation.

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
