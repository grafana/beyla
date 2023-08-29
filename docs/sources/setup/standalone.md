---
title: Run as a standalone process
menuTitle: Standalone
description: Learn how to run Grafana's eBPF auto-instrumentation tool as a standalone Linux process.
weight: 1
---

# Run as a standalone process

The eBPF auto-instrumentation tool can run as a standalone Linux OS process with
elevated privileges, which can inspect other running processes.

For a quick introduction about how to collect and visualize the instrumented
data, you can follow our [step-by-step tutorial]({{< relref "../tutorial/index.md" >}}).

## Download and install Beyla - the eBPF auto-instrumentation tool

You can download the auto-instrumentation executable directly with the `go install`
command line:

```sh
go install github.com/grafana/ebpf-autoinstrument/cmd/beyla@latest
```

## Specifying configuration options

The eBPF auto-instrumentation tool can be configured via:

* Environment variables.
* A YAML configuration file path, passed in with the `-config` CLI argument.

If the same configuration property is defined in both the YAML file and the environment
variables, the value specified in the environment variables takes precedence over the
configuration file.

For a complete list and description of all of the configuration options, you can check the
[list of configuration options]({{< relref "../configure/options" >}}) documentation section.

## Running the auto-instrumentation tool

The eBPF auto-instrumentation tool requires at least two configuration options to run:

* The executable to instrument. You can select which executable to instrument by its
  command line name or by any port it has open.
* A metrics exporter. You can configure an OpenTelemetry metrics and/or traces exporter, but
  you can also configure a Prometheus HTTP endpoint to expose the metrics.

The eBPF auto-instrumentation tool requires `sudo`/administrative processes privileges, or at
least it needs to be granted the `CAP_SYS_ADMIN` capability.

## Examples

Let's instrument the process that owns the port 443, and expose the metrics as a
Prometheus endpoint listening on the port 8999. In this example, the configuration is passed
exclusively through environment variables:

```sh
BEYLA_PROMETHEUS_PORT=8999 OPEN_PORT=443 sudo -E beyla
```

The equivalent execution, but configured via a YAML file would look like:

```yaml
cat > config.yml <<EOF
ebpf:
  open_port: 443
prometheus_export:
  port: 8999
EOF
sudo beyla -config config.yml
```

In the following example, we are overriding the previous YAML configuration option
for the Prometheus port, via an environment variable:

```
BEYLA_PROMETHEUS_PORT=8888 sudo -E beyla -config config.yml
```
