
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
