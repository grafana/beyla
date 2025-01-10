
### Selection of metric attributes

The [Beyla exported metrics]({{< relref "../metrics.md" >}}) document lists the attributes
that can be reported with each metric. Some of the attributes are reported by default while
others are hidden to control the cardinality.

For each metric, you can control which attributes to see with the `select` subsection, which
is a map where each key is the name of a metric (either in its OpenTelemetry or Prometheus port),
and each metric has two more sub-properties: `include` and `exclude`.

* `include` is a list of attributes that need to be reported. Each attribute can be an attribute
  name or a wildcard (for example, `k8s.dst.*` to include all the attributes starting with `k8s.dst`).
  If no `include` list is provided, the default attribute set is reported (check [Beyla exported metrics]({{< relref "../metrics.md" >}})
  for more information about the default attributes for a given metric).
* `exclude` is a list to of attribute names/wildcards containing the attributes to remove from the
  `include` list (or the default attribute set).

Example:
```yaml
attributes:
  select:
    beyla_network_flow_bytes:
      # limit the beyla_network_flow_bytes attributes to only the three attributes
      include:
        - beyla.ip
        - src.name
        - dst.port
    sql_client_duration:
      # report all the possible attributes but db_statement
      include: ["*"]
      exclude: ["db_statement"]
    http_client_request_duration:
      # report the default attribute set but exclude the Kubernetes Pod information
      exclude: ["k8s.pod.*"]
```

Additionally, you can use "`*`" wildcards as metric names to add and exclude attributes for
groups of metrics having the same name. For example:

```yaml
attributes:
  select:
    http_*:
      include: ["*"]
      exclude: ["http_path", "http_route"]
    http_client_*:
      # override http_* exclusion
      include: ["http_path"]
    http_server_*:
      # override http_* exclusion
      include: ["http_route"]
```

In the previous example, all the metrics with a name starting with `http_` (or `http.`) would include all
the possible attributes but `http_path` and `http_route` (or `http.path`/`http.route`).
The `http_client_*` and `http_server_*` sections would override the base configuration, enabling the
`http_path` attribute for the HTTP client metrics and `http_route` for the HTTP server metrics.

When a metric name matches multiple definitions using wildcards, exact matches have higher precedence than wild card matches.

## Other attributes

| YAML                    | Environment variable              | Type    | Default |
| ----------------------- | --------------------------------- | ------- | ------- |
| `track_request_headers` | `BEYLA_BPF_TRACK_REQUEST_HEADERS` | boolean | (false) |

Enables tracking of request headers for the purposes of processing any incoming 'Traceparent'
header values. If this option is enabled, when Beyla encounters an incoming server request with
a 'Traceparent' header value, it will use the provided 'trace id' to create its own trace spans.

This option does not have an effect on Go applications, where the 'Traceparent' field is always
processed, without additional tracking of the request headers.

Enabling this option may increase the performance overhead in high request volume scenarios.
This option is only useful when generating Beyla traces, it does not affect
generation of Beyla metrics.

| YAML                    | Environment variable               | Type     | Default |
| ----------------------- | ---------------------------------- | -------- | ------- |
| `heuristic_sql_detect`   | `BEYLA_HEURISTIC_SQL_DETECT`      | boolean  | (false) |

By default, Beyla detects various SQL client requests through detection of their
particular binary protocol format. However, oftentimes SQL database clients send their
queries in a format where Beyla can detect the query statement without knowing
the exact binary protocol. If you are using a database technology not directly supported
by Beyla, you can enable this option to get database client telemetry. The option is
not enabled by default, because it can create false positives, for example, an application
sending SQL text for logging purposes through a TCP connection. Currently supported
protocols where this option isn't needed are the Postgres and MySQL binary protocols.
