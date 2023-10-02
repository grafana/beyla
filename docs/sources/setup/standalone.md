---
title: Run Beyla as a standalone process
menuTitle: Standalone
description: Learn how to setup and run Beyla as a standalone Linux process.
weight: 1
keywords:
  - Beyla
  - eBPF
---

# Run Beyla as a standalone process

Beyla can run as a standalone Linux OS process with elevated privileges that can inspect other running processes.

For a complete introduction tutorial on how to collect and visualize the instrumented data, follow the [quick start tutorial]({{< relref "../tutorial/index.md" >}}).

## Download and install

You can download the Beyla executable from the [Beyla releases page](https://github.com/grafana/beyla/releases).

Alternatively, download the Beyla executable with the `go install` command:

```sh
go install github.com/grafana/beyla/cmd/beyla@latest
```

## Configure

Beyla can be configured via:

- environment variables
- a YAML configuration file, supplied with the `-config` CLI argument

If the same configuration property is defined in both the YAML file and the environment
variables, the value specified in the environment variables takes precedence over the
configuration file.

For a complete list of configuration options, see the [Beyla configuration options]({{< relref "../configure/_index.md" >}}) documentation.

## Run

Beyla requires at least two configuration options to run:

- the executable to instrument, specified with the command line name or port
- a metrics exporter, either OpenTelemetry or Prometheus

Beyla requires administrative (sudo) privileges, or at least it needs to be granted the `CAP_SYS_ADMIN` capability.

## Examples

Let's instrument the process that owns the port 443, and expose the metrics as a Prometheus endpoint listening on the port 8999. In this example, the configuration is passed exclusively through environment variables:

```sh
BEYLA_PROMETHEUS_PORT=8999 OPEN_PORT=443 sudo -E beyla
```

The equivalent execution, but configured via a YAML file would look like:

```yaml
cat > config.yml <<EOF
open_port: 443
prometheus_export:
  port: 8999
EOF
sudo beyla -config config.yml
```

In the following example, the previous YAML configuration option for the Prometheus port is overridden by an environment variable:

```
BEYLA_PROMETHEUS_PORT=8888 sudo -E beyla -config config.yml
```
