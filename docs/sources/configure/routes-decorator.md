---
title: Configure Beyla routes decorator
menuTitle: Routes decorator
description: Configure the routes decorator component before Beyla sends data to the next stage of the pipeline.
weight: 50
keywords:
  - Beyla
  - eBPF
---

# Configure Beyla routes decorator

You can configure the component under the `routes` section of your YAML configuration or via environment variables.

This section can be only configured via the YAML file. If no `routes` section is provided in
the YAML file, a default routes' pipeline stage will be created and filtered with the `heuristic`
routes decorator.

| YAML       | Environment variable | Type            | Default |
| ---------- | ------- | --------------- | ------- |
| `patterns` | --      | list of strings | (unset) |

Will match the provided URL path patterns and set the `http.route` trace/metric
property accordingly. You should use the `routes` property
whenever possible to reduce the cardinality of generated metrics.

Each route pattern is a URL path with specific tags which allow for grouping path
segments. The matcher tags can be in the `:name` or `{name}` format.

For example, if you define the following patterns:

```yaml
routes:
  patterns:
    - /user/{id}
    - /user/{id}/basket/{product}
```

Traces with the following HTTP paths will include the same `http.route='/user/{id}'` property:

```
/user/123
/user/456
```

Traces with the following HTTP paths will include the same `http.route='/user/{id}'/basket/{product}`
property:

```
/user/123/basket/1
/user/456/basket/3
```

Additionally, the route matcher also supports the wildcard character `*`, which can be used to
match path prefixes. For example, if you define the following pattern:

```yaml
routes:
  patterns:
    - /user/*
```

Any traces with HTTP paths starting with `/user` (including `/user` itself) will be matched to the
route `/user/*`. As per the example above, all of the following paths will be matched as `/user/*`:

```
/user
/user/123
/user/123/basket/1
/user/456/basket/3
```

| YAML               | Environment variable | Type            | Default |
| ------------------ | ------- | --------------- | ------- |
| `ignored_patterns` | --      | list of strings | (unset) |

Will match the provided URL path against the defined patterns, and discard the trace and/or metric events if
they match any of the `ignored_patterns`. The format for the `ignored_patterns` field is identical
to the `patterns` field described above. You can define the ignored patterns with or without
any of the wildcard options. For example, if you define the following ignored patterns:

```yaml
routes:
  ignored_patterns:
    - /health
    - /v1/*
```

Any event paths which have a prefix of `/v1` or are equal to `/health` will be ignored.

This option is very useful if you want to prevent certain paths used development or service health monitoring, to be
recorded as traces or metrics.

| YAML          | Environment variable | Type   | Default |
| ------------- | ------- | ------ | ------- |
| `ignore_mode` | --      | string | `all`   |

This property can be used together with the `ignored_patterns` property to refine which type of events are ignored.

Possible values for the `ignore_mode` property are:

- `all` will discard both **metrics** and **traces** which match the `ignored_patterns`.
- `traces` will discard only the **traces** which match the `ignored_patterns`. No metric events will be ignored.
- `metrics` will discard only the **metrics** which match the `ignored_patterns`. No trace events will be ignored.

Selectively ignoring only certain type of events might be useful in certain scenarios. For example, you may want to
know the performance metrics of your health check API, but you wouldn't want the overhead of those trace records in
your target traces database. In this example scenario, you would set the `ignore_mode` property to `traces`, such
that only traces matching the `ignored_patterns` will be discarded, while metrics will still be recorded.

| YAML        | Environment variable | Type   | Default    |
| ----------- | ------- | ------ | ---------- |
| `unmatched` | --      | string | `heuristic` |

Specifies what to do when a trace HTTP path does not match any of the `patterns` entries.

Possible values for the `unmatched` property are:

- `unset` will leave the `http.route` property as unset.
- `path` will copy the `http.route` field property to the path value.
  - 🚨 Caution: this option could lead to cardinality explosion at the ingester side.
- `wildcard` will set the `http.route` field property to a generic asterisk based `/**` value.
- `heuristic` will automatically derive the `http.route` field property from the path value, based on the following rules:
  - Any path components which have numbers or characters outside of the ASCII alphabet (or `-` and `_`), are replaced by `wildcard_char`.
  - Any alphabetical components which don't look like words, are replaced by `wildcard_char`.

| YAML        | Environment variable | Type   | Default    |
| ----------- | ------- | ------ | ---------- |
| `wildcard_char` | --      | string | `'*'` |

Can be used together with `unmatched: heuristic` to choose what character the path components identified by the heuristic mode are replaced by. By default, an asterisk (`'*'`) is used. The value should be quoted and must be a single character.

### Special considerations when using the `heuristic` route decorator mode

The `heuristic` decorator is a best effort route decorator, which may still lead to cardinality explosion in certain scenarios.
For example, the GitHub URL paths are a good example where the `heuristic` route decorator will not work, since the URL paths
are constructed like a directory tree. In this scenario all paths will remain unique and lead to cardinality explosion.

On the other hand, if your URL path patterns follow certain structure, and the unique IDs are made up of numbers or random characters,
then the `heuristic` decorator may be a low effort configuration option which is suitable for your use-case. For example, the following
mock Google Docs URLs will be correctly reduced to a low cardinality version:

Both URL paths below:

```
document/d/CfMkAGbE_aivhFydEpaRafPuGWbmHfG/edit (no numbers in the ID)
document/d/C2fMkAGb3E_aivhFyd5EpaRafP123uGWbmHfG/edit
```

are converted to a low cardinality route (using the default `wildcard_char`):

```
document/d/*/edit
```

