---
title: Beyla global configuration properties
menuTitle: Global properties
description: Configure global configuration properties that apply to Beyla core.
weight: 2
keywords:
  - Beyla
  - eBPF
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/configure/options/
---

# Beyla global configuration properties

Beyla can be configured via environment variables or via
a YAML configuration file that is passed either with the `-config` command-line
argument or the `BEYLA_CONFIG_PATH` environment variable.
Environment variables have priority over the properties in the
configuration file. For example, in the following command line, the `BEYLA_OPEN_PORT` option,
is used to override any `open_port` settings inside the config.yaml file:

```
$ BEYLA_OPEN_PORT=8080 beyla -config /path/to/config.yaml
```

or

```
$ BEYLA_OPEN_PORT=8080 BEYLA_CONFIG_PATH=/path/to/config.yaml beyla
```

Refer to the [example YAML configuration file](../example/) for configuration file template.

Currently, Beyla consist of a pipeline of components which
generate, transform, and export traces from HTTP and GRPC applications. In the
YAML configuration, each component has its own first-level section.

Optionally, Beyla also provides network-level metrics, which are documented in the
[Network metrics section of the Beyla documentation](../../network/).

The following sections explain the global configuration properties, as well as
the options for each component.

## Global configuration properties

| YAML        | Environment variable           | Type   | Default |
| ----------- | ----------------- | ------ | ------- |
| `log_level` | `BEYLA_LOG_LEVEL` | string | `INFO`  |

Sets the verbosity level of the process standard output logger.
Valid log level values are: `DEBUG`, `INFO`, `WARN` and `ERROR`.
`DEBUG` being the most verbose and `ERROR` the least verbose.

| YAML            | Environment variable  | Type    | Default    |
| --------------  | --------------------- | ------- | ---------- |
| `trace_printer` | `BEYLA_TRACE_PRINTER` | string  | `disabled` |

<a id="printer"></a>

Prints any instrumented trace on the standard output. The value of
this option specify the format to be used when printing the trace. Valid
formats are:

| Value         | Description                    |
|---------------|--------------------------------|
| `disabled`    | disables the printer           |
| `text`        | prints a concise line of text  |
| `json`        | prints a compact JSON object   |
| `json_indent` | prints an indented JSON object |

| YAML               | Environment variable     | Type     | Default    |
| -----------------  | ------------------------ | -------- | ---------- |
| `enforce_sys_caps` | `BEYLA_ENFORCE_SYS_CAPS` | boolean  | `false`    |

<a id="caps"></a>

If you have set the `enforce_sys_caps` to true, if the required system
capabilities are not present Beyla aborts its startup and logs a list of the
missing capabilities.

If you have set the configuration option to `false`, Beyla logs a list of the
missing capabilities only.
