# Running as a standalone process

The eBPF Autoinstrument can run as a standalone Operating System process with
elevated privileges, which can inspect other running processes.

For a quick introduction about how to run it and visualize the instrument
data, you can also follow our [step-by-step tutorial](./tutorial/README.md).

## Download the eBPF autoinstrument

You can download the Autoinstrument executable directly with `go install`:

```
go install github.com/grafana/ebpf-autoinstrument/cmd/otelauto@latest
```

## Configuring

The eBPF autoinstrument can be configured from two non-exclusive sources:

* Via environment variables.
* Via a YAML configuration whose path is passed with the `-config` CLI argument.

If a configuration property is defined both in the YAML file and the environment
variables, the value in the environment variable takes precedence over the
configuration file.

For a complete description of the configuration values, you can check the
[list of configuration options](config.md).

## Running

The eBPF Autoinstrument requires at least two configuration options to run:

* A selector of the executable to instrument. You can select it by executable name 
  or by any port it has open.
* A metrics exporter. It can push OpenTelemetry metrics and/or traces, and
  can also opens a Prometheus HTTP endpoint to expose the metrics.

The eBPF Autoinstrument process requires `sudo`/administrative processes, or at
least being granted with the `CAP_SYS_ADMIN` capability.

## Examples

Instrument the process that owns the port 443, and expose the Metrics as a
Prometheus endpoint listening in the port 8999. The configuration is passed
exclusively as environment variables:

```
$ PROMETHEUS_PORT=8999 OPEN_PORT=443 sudo -E otelauto
```

The equivalent execution, but configured via YAML file:

```
$ cat > config.yml <<EOF
ebpf:
  open_port: 443
prometheus_export:
  port: 8999
EOF
$ sudo otelauto -config config.yml
```

The previous YAML configuration can be overriden via environment variables:

```
$ PROMETHEUS_PORT=8888 sudo -E otelauto -config config.yml
```