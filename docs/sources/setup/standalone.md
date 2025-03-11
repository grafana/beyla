---
title: Run Beyla as a standalone process
menuTitle: Standalone
description: Learn how to setup and run Beyla as a standalone Linux process.
Draft: true
weight: 1
keywords:
  - Beyla
  - eBPF
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/setup/standalone/
---

![Grafana Beyla Logo](https://grafana.com/media/docs/grafana-cloud/beyla/beyla-logo-2.png)

# Run Beyla as a standalone process

Beyla can run as a standalone Linux OS process with elevated privileges that can inspect other running processes.

## Download and install

You can download the Beyla executable from the [Beyla releases page](https://github.com/grafana/beyla/releases).

Alternatively, download the Beyla executable with the `go install` command:

```sh
go install github.com/grafana/beyla/cmd/beyla@latest
```

## Installing as a service

Once you have Beyla installed on your system, you can use the [systemd service script](https://github.com/grafana/beyla/tree/main/contrib/beyla@.service) to get the daemon up and running. Installing the script is as simple as creating a file at `/etc/systemd/system/beyla@.service` (the `@` is important!) and running `systemctl daemon-reload`.

The systemd service expects the following requirements to be met:

- The `beyla` binary is in `/usr/local/bin` and is executable
- A directory exists at `/etc/beyla` to hold the various configuration files

The service script works in such a way that it will pick up the files named after the service name that follows the `@` sign. As an example, if we wanted to use Beyla to monitor a moodle installation, we would create a configuration file at `/etc/beyla/moodle.yaml` and place our environment variables in `/etc/beyla/moodle.env`, then start the service with the command `systemctl start beyla@moodle.service` - the service will automatically pick up the `moodle` related files and start monitoring.

If you want to add a second Beyla install on the same system monitoring a Django installation, you would create `/etc/beyla/django.yaml` and `/etc/beyla/django.env`, then start the service as `systemctl start beyla@django` and it will run alongside the existing Moodle Beyla but with the Django configuration.

## Configure

Beyla can be configured via:

- environment variables
- a YAML configuration file, supplied with the `-config` CLI argument

If the same configuration property is defined in both the YAML file and the environment
variables, the value specified in the environment variables takes precedence over the
configuration file.

For a complete list of configuration options, see the [Beyla configuration options](../../configure/) documentation.

## Run

Beyla requires at least two configuration options to run:

- the executable to instrument, specified with the command line name or port
- a metrics exporter, either OpenTelemetry or Prometheus

Beyla requires administrative (sudo) privileges, or at least it needs to be granted the `CAP_SYS_ADMIN` capability.

## Examples

Let's instrument the process that owns the port 443, and expose the metrics as a Prometheus endpoint listening on the port 8999. In this example, the configuration is passed exclusively through environment variables:

```sh
BEYLA_PROMETHEUS_PORT=8999 BEYLA_OPEN_PORT=443 sudo -E beyla
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
