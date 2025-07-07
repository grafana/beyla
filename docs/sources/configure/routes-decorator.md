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

YAML section: `routes`

You can configure the component under the `routes` section of your YAML configuration or with environment variables.

You must configure this section in the YAML file. If you don't provide a `routes` section, Beyla creates a default routes pipeline stage and uses the `heuristic` routes decorator.

For example:

```yaml
routes:
  patterns:
    - /basic/:rnd
  unmatched: path
  ignored_patterns:
    - /metrics
  ignore_mode: traces
```

| YAML               | Description                                                                                                                   | Type            | Default   |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------- | --------------- | --------- |
| `patterns`         | List of URL path patterns to match and set the `http.route` property. Refer to [patterns](#patterns).                         | list of strings | (unset)   |
| `ignored_patterns` | List of URL path patterns to ignore. Discards trace/metric events if matched. Refer to [ignored patterns](#ignored-patterns). | list of strings | (unset)   |
| `ignore_mode`      | Refines which type of events are ignored when using `ignored_patterns`. Refer to [ignore mode](#ignore-mode).                 | string          | all       |
| `unmatched`        | Specifies what to do when a trace HTTP path doesn't match any `patterns` entries. Refer to [unmatched](#unmatched).           | string          | heuristic |
| `wildcard_char`    | Character to use for path components replaced by the heuristic mode. Refer to [wildcard char](#wildcard-char).                | string          | "*"      |

## Patterns

Beyla matches the provided URL path patterns and sets the `http.route` trace/metric property. Use the `routes` property whenever possible to reduce the cardinality of generated metrics.

Each route pattern is a URL path with tags that group path segments. You can use the `:name` or `{name}` format for the matcher tags.

For example, if you define the following patterns:

```yaml
routes:
  patterns:
    - /user/{id}
    - /user/{id}/basket/{product}
```

Traces with these HTTP paths include the same `http.route='/user/{id}'` property:

```
/user/123
/user/456
```

Traces with these HTTP paths include the same `http.route='/user/{id}'/basket/{product}` property:

```
/user/123/basket/1
/user/456/basket/3
```

The route matcher also supports the wildcard character `*`, which matches path prefixes. For example, if you define this pattern:

```yaml
routes:
  patterns:
    - /user/*
```

Any traces with HTTP paths starting with `/user` (including `/user` itself) match the route `/user/*`. All of the following paths match as `/user/*`:

```
/user
/user/123
/user/123/basket/1
/user/456/basket/3
```

## Ignored patterns

Beyla matches the provided URL path against the defined patterns and discards the trace and/or metric events if they match any of the `ignored_patterns`. The format for the `ignored_patterns` field is identical to the `patterns` field. You can define the ignored patterns with or without any of the wildcard options. For example, if you define these ignored patterns:

```yaml
routes:
  ignored_patterns:
    - /health
    - /v1/*
```

Any event paths with a prefix of `/v1` or equal to `/health` are ignored.

This option is useful if you want to prevent certain paths used for development or service health monitoring from being recorded as traces or metrics.

## Ignore mode

Use this property with the `ignored_patterns` property to refine which type of events are ignored.

Possible values for the `ignore_mode` property are:

- `all` discards both **metrics** and **traces** that match the `ignored_patterns`
- `traces` discards only the **traces** that match the `ignored_patterns`, no metric events are ignored
- `metrics` discards only the **metrics** that match the `ignored_patterns`, no trace events are ignored

If you want to ignore certain types of events, for example, you may want to know the performance metrics of your health check API, but you don't want the overhead of those trace records in your traces database. In this case, set the `ignore_mode` property to `traces`, so only traces matching the `ignored_patterns` are discarded, while metrics are still recorded.

## Unmatched

This property specifies what to do when a trace HTTP path doesn't match any of the `patterns` entries.

Possible values for the `unmatched` property are:

- `unset` leaves the `http.route` property unset
- `path` copies the `http.route` field property to the path value. This option can lead to cardinality explosion at the ingestion side
- `wildcard` sets the `http.route` field property to a generic asterisk-based `/**` value
- `heuristic` automatically derives the `http.route` field property from the path value, based on these rules:
  - Any path components with numbers or characters outside of the ASCII alphabet (or `-` and `_`) are replaced by `wildcard_char`
  - Any alphabetical components that don't look like words are replaced by `wildcard_char`

## Wildcard char

Use this property with `unmatched: heuristic` to choose what character the path components identified by the heuristic mode are replaced by. By default, Beyla uses an asterisk `'*'`. The value should be quoted and must be a single character.

## Heuristic route decorator mode

The `heuristic` decorator is a best effort route decorator, which may still lead to cardinality explosion in some scenarios.
For example, the GitHub URL paths are a good example where the `heuristic` route decorator won't work, since the URL paths are constructed like a directory tree. In this scenario, all paths remain unique and lead to cardinality explosion.

If your URL path patterns follow a certain structure, and the unique IDs are made up of numbers or random characters, then the `heuristic` decorator may be a low effort configuration option that works for your use case. For example, the following mock Google Docs URLs are correctly reduced to a low cardinality version:

Both URL paths below:

```
document/d/CfMkAGbE_aivhFydEpaRafPuGWbmHfG/edit (no numbers in the ID)
document/d/C2fMkAGb3E_aivhFyd5EpaRafP123uGWbmHfG/edit
```

are converted to a low cardinality route (using the default `wildcard_char`):

```
document/d/*/edit
```
