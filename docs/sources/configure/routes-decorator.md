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

You can configure this component in the `routes` section of your YAML configuration or with environment variables.

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

| YAML               | Description                                                                                                                        | Type            | Default   |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------- | --------------- | --------- |
| `patterns`         | List of URL path patterns to match and set the `http.route` property. Refer to [patterns](#patterns).                              | list of strings | (unset)   |
| `ignored_patterns` | List of URL path patterns to ignore. Discards trace/metric events if matched. Refer to [ignored patterns](#ignored-patterns).      | list of strings | (unset)   |
| `ignore_mode`      | Specifies which event types to ignore when using `ignored_patterns`. Refer to [ignore mode](#ignore-mode).                         | string          | all       |
| `unmatched`        | Specifies what to do when an HTTP path doesn't match any `patterns` entries. Refer to [unmatched](#unmatched).                     | string          | heuristic |
| `wildcard_char`    | Character to use for path components replaced by cardinality reducing modes. Refer to [wildcard char](#wildcard-char).             | string          | "*"       |
| `max_path_segment_cardinality` | Maximum cardinality in a segment for the low-cardinality unmatched mode.                                               | int             | 10       |

## Patterns

Beyla matches the provided URL path patterns and sets the `http.route` trace/metric property. Use the `routes` property when possible to reduce the cardinality of generated metrics.

Each route pattern is a URL path with tags that group path segments. You can use the `:name` or `{name}` format for matcher tags.

For example, if you define these patterns:

```yaml
routes:
  patterns:
    - /user/{id}
    - /user/{id}/basket/{product}
```

Traces with these HTTP paths have the same `http.route='/user/{id}'` property:

```
/user/123
/user/456
```

Traces with these HTTP paths have the same `http.route='/user/{id}'/basket/{product}` property:

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

Any traces with HTTP paths starting with `/user` (including `/user` itself) match the route `/user/*`. All these paths match as `/user/*`:

```
/user
/user/123
/user/123/basket/1
/user/456/basket/3
```

## Ignored patterns

Beyla matches the provided URL path against the defined patterns and discards trace or metric events if they match any `ignored_patterns`. The format for `ignored_patterns` is identical to `patterns`. You can define ignored patterns with or without wildcard options. For example, if you define these ignored patterns:

```yaml
routes:
  ignored_patterns:
    - /health
    - /v1/*
```

Any event paths with a prefix of `/v1` or equal to `/health` are ignored.

This is useful to prevent certain paths used for development or service health monitoring from being recorded as traces or metrics.

## Ignore mode

Use this property with `ignored_patterns` to specify which event types to ignore.

Possible values for `ignore_mode` are:

- `all` discards both **metrics** and **traces** that match `ignored_patterns`
- `traces` discards only **traces** that match `ignored_patterns`, metrics are still recorded
- `metrics` discards only **metrics** that match `ignored_patterns`, traces are still recorded

For example, you may want performance metrics for your health check API but not the overhead of trace records in your traces database. Set `ignore_mode` to `traces` so only traces matching `ignored_patterns` are discarded, while metrics are still recorded.

## Unmatched

This property specifies what to do when an HTTP path doesn't match any `patterns` entries.

Possible values for `unmatched` are:

- `unset` leaves the `http.route` property unset
- `path` copies the path value to the `http.route` field. This can lead to cardinality explosion at the ingestion side
- `wildcard` sets the `http.route` field to a generic asterisk-based `/**` value
- [`heuristic`](#heuristic-route-decorator-mode) automatically derives `http.route` from the path value using these rules:
  - Path components with numbers or characters outside the ASCII alphabet (or `-` and `_`) are replaced by `wildcard_char`
  - Alphabetical components that don't look like words are replaced by `wildcard_char`
- [`low-cardinality`](#low-cardinality-route-decorator-mode) automatically derives `http.route` from the path value, ensuring path components with
  unbounded cardinality are replaced with `wildcard_char`.

## Wildcard char

Use this property with `unmatched: heuristic` to choose the character that replaces path components identified by heuristic mode. By default, Beyla uses an asterisk `'*'`. The value should be quoted and must be a single character.

## Heuristic route decorator mode

The `heuristic` decorator is a best effort route decorator, which may still lead to cardinality explosion in some scenarios.
For example, GitHub URL paths are constructed like a directory tree, so all paths remain unique and lead to cardinality explosion. In this case consider the [low-cardinality](#low-cardinality-route-decorator-mode) route decorator.

If your URL path patterns follow a certain structure and unique IDs are made of numbers or random characters, then the `heuristic` decorator may work for your use case with minimal configuration. For example, these mock Google Docs URLs are correctly reduced to a low cardinality version:

Both URL paths below:

```
document/d/CfMkAGbE_aivhFydEpaRafPuGWbmHfG/edit (no numbers in the ID)
document/d/C2fMkAGb3E_aivhFyd5EpaRafP123uGWbmHfG/edit
```

are converted to a low cardinality route (using the default `wildcard_char`):

```
document/d/*/edit
```

## Low cardinality route decorator mode

Low cardinality route decorator mode extends the [`heuristic`](#heuristic-route-decorator-mode) mode by performing additional cardinality reduction after applying heuristics.

The cardinality reduction logic detects cardinality explosion in specific URL path segments using this process:

1. It builds a per-service route database by deconstructing URL path segments into nodes. For example, with `/api/users/123`, there are three nodes: `api` -> `users` -> `123`.
2. Each URL path segment node tracks how many unique children it has. For example, when processing `/api/users/abc`, `/api/users/def`, `/api/users/xyz`, the `users` node sees its children cardinality increase to 3.
3. High cardinality URL path segment nodes are automatically collapsed when a threshold is reached. When a node's children exceed `max_path_segment_cardinality`, all children merge into a single wildcard node (`wildcard_char`). Future paths through that segment return the `wildcard_char`.

Example flow with `low-cardinality` mode and `max_path_segment_cardinality=3`:

  Insert `/api/users/alice`  -> `/api/users/alice`   (cardinality: 1)
  Insert `/api/users/bob`    -> `/api/users/bob`     (cardinality: 2)
  Insert `/api/users/carol`  -> `/api/users/carol`   (cardinality: 3)
  Insert `/api/users/dave`   -> `/api/users/*`       (threshold exceeded, collapsed)
  Insert `/api/users/eve`    -> `/api/users/*`       (stays collapsed)

This means the first three routes match the original URL path. After the cardinality limit is reached, all future URL paths collapse to a low cardinality route.

Note that the per-service low-cardinality route database is in-memory only and resets on every Beyla restart.