---
title: Run Beyla on a Linux host
menuTitle: Linux host
description: Download the Grafana Beyla binary, run it on a Linux host to instrument a service, and send metrics and traces to a backend or run Beyla as a systemd service.
weight: 100
keywords:
  - Beyla
  - eBPF
  - Linux
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/setup/standalone/
  - ../quickstart/ # /docs/beyla/<BEYLA_VERSION>/quickstart/
  - ../quickstart/cpp/ # /docs/beyla/<BEYLA_VERSION>/quickstart/cpp/
  - ../quickstart/golang/ # /docs/beyla/<BEYLA_VERSION>/quickstart/golang/
  - ../quickstart/java/ # /docs/beyla/<BEYLA_VERSION>/quickstart/java/
  - ../quickstart/nodejs/ # /docs/beyla/<BEYLA_VERSION>/quickstart/nodejs/
  - ../quickstart/python/ # /docs/beyla/<BEYLA_VERSION>/quickstart/python/
  - ../quickstart/ruby/ # /docs/beyla/<BEYLA_VERSION>/quickstart/ruby/
  - ../quickstart/rust/ # /docs/beyla/<BEYLA_VERSION>/quickstart/rust/
---

# Run Beyla on a Linux host

You can run Grafana Beyla as a process on a Linux host, such as a virtual machine or a bare-metal server.
Beyla runs with elevated privileges and instruments services that run on the same host, without changes to the services.
The steps are the same for services written in any language that Beyla supports.

## Before you begin

Before you run Beyla, make sure you have the following:

- A Linux host on `amd64` or `arm64`, with a kernel that meets the [Beyla requirements and limitations][requirements]
- Root access with `sudo`, or the Linux capabilities listed in [Beyla security, permissions, and capabilities][security]
- A service on the host that listens on a TCP port, for example an HTTP, HTTPS, or gRPC service

## Start an example service

To try Beyla before you instrument your own service, start one of the example services from the [`examples/quickstart`][examples] directory of the Beyla repository.
Each example is an HTTP service that listens on port `8080`.
If you instrument your own service, skip this section.

| Language | Files                                         | Start command                                                  |
| -------- | --------------------------------------------- | -------------------------------------------------------------- |
| C/C++    | `cpp/httplib.h`, `cpp/quickstart.cpp`         | `g++ -std=c++11 quickstart.cpp -o quickstart && ./quickstart`  |
| Go       | `golang/quickstart.go`                        | `go run quickstart.go`                                         |
| Java     | `java/Quickstart.java`                        | `javac Quickstart.java && java Quickstart`                     |
| Node.js  | `nodejs/package.json`, `nodejs/quickstart.js` | `npm install && npm start`                                     |
| Python   | `python/quickstart.py`                        | `python3 quickstart.py`                                        |
| Ruby     | `ruby/quickstart.rb`                          | `ruby quickstart.rb`                                           |
| Rust     | `rust/quickstart.rs`                          | `rustc quickstart.rs && ./quickstart`                          |

For example, to download and start the Go example:

```sh
curl -OL https://raw.githubusercontent.com/grafana/beyla/main/examples/quickstart/golang/quickstart.go
go run quickstart.go
```

## Download and install Beyla

Beyla releases include a Linux binary for `amd64` and `arm64`.

1. Download the archive for your host from the [Beyla releases page][releases]:

   ```sh
   curl -LO https://github.com/grafana/beyla/releases/download/<VERSION>/beyla-linux-<ARCH>-<VERSION>.tar.gz
   ```

   Replace the following:

   - _`<VERSION>`_: The Beyla release tag, for example `v3.40.0`
   - _`<ARCH>`_: The host architecture, `amd64` or `arm64`

1. Extract the `beyla` binary and install it in `/usr/local/bin`:

   ```sh
   tar -xzf beyla-linux-<ARCH>-<VERSION>.tar.gz beyla
   sudo install beyla /usr/local/bin/
   ```

## Run Beyla

Beyla needs a way to select the process to instrument, and at least one exporter.
The following commands instrument the process that opens port `8080` and print traces to standard output, so you don't need a backend:

```sh
export BEYLA_OPEN_PORT=8080
export BEYLA_TRACE_PRINTER=text
sudo -E beyla
```

The commands set these environment variables:

| Environment variable  | Description                                                                                           |
| --------------------- | ----------------------------------------------------------------------------------------------------- |
| `BEYLA_OPEN_PORT`     | Selects the process to instrument by the port it opens. Replace `8080` with the port of your service. |
| `BEYLA_TRACE_PRINTER` | Prints traces to standard output. `text` prints one line per request.                                 |

The `-E` option of `sudo` passes the exported variables to Beyla.

You can also set options in a YAML configuration file.
Pass the file with the `-config` argument or the `BEYLA_CONFIG_PATH` environment variable.
If you set an option in both the file and an environment variable, the environment variable takes precedence.

## Check that Beyla instruments the service

Send a request to the service:

```sh
curl http://localhost:8080/foo
```

Beyla prints one line for each request it captures.
Each line includes the start time and duration of the request, the protocol, the response status code, the HTTP method and path, the route, the source and destination addresses, the request and response sizes, the service name, and the trace context.

## Send data to a backend

The trace printer is for testing.
To send data to a backend, unset `BEYLA_TRACE_PRINTER` and set exporter options instead.

To send metrics and traces to an OpenTelemetry endpoint, such as Grafana Cloud, set the OTLP environment variables:

```sh
unset BEYLA_TRACE_PRINTER
export BEYLA_OPEN_PORT=<SERVICE_PORT>
export OTEL_EXPORTER_OTLP_PROTOCOL="http/protobuf"
export OTEL_EXPORTER_OTLP_ENDPOINT="<OTLP_ENDPOINT>"
export OTEL_EXPORTER_OTLP_HEADERS="<OTLP_HEADERS>"
sudo -E beyla
```

Replace the following:

- _`<SERVICE_PORT>`_: The port your service opens
- _`<OTLP_ENDPOINT>`_: The URL of your OTLP endpoint.
  For Grafana Cloud, copy the endpoint from the **OpenTelemetry** tile of your stack.
- _`<OTLP_HEADERS>`_: The headers your endpoint needs, such as authentication, as comma-separated `key=value` pairs.
  For Grafana Cloud, copy the `OTEL_EXPORTER_OTLP_HEADERS` value that the **OpenTelemetry** tile generates.

For Grafana Cloud, follow the procedure in [Send data to the Grafana Cloud OTLP endpoint][cloud-otlp].

To expose metrics for Prometheus to scrape, set the Prometheus port:

```sh
unset BEYLA_TRACE_PRINTER
export BEYLA_OPEN_PORT=<SERVICE_PORT>
export BEYLA_PROMETHEUS_PORT=8999
sudo -E beyla
```

Replace _`<SERVICE_PORT>`_ with the port your service opens.

Beyla serves the metrics at `http://localhost:8999/metrics`.

For all export options, refer to [Configure Beyla Prometheus and OpenTelemetry data export][export-data].

## Run Beyla as a systemd service

To keep Beyla running and start it when the host boots, run Beyla as a systemd service.
The Beyla repository includes a [systemd unit file][unit].
The unit runs `/usr/local/bin/beyla` as `root`, reads environment variables from `/etc/beyla/beyla.env`, and loads the configuration file `/etc/beyla/beyla.yaml`.

1. Create the configuration directory:

   ```sh
   sudo mkdir -p /etc/beyla
   ```

1. Create `/etc/beyla/beyla.yaml` to select the service to instrument:

   ```yaml
   discovery:
     instrument:
       - open_ports: <SERVICE_PORT>
   ```

   Replace _`<SERVICE_PORT>`_ with the port your service opens.

1. Create `/etc/beyla/beyla.env` with the exporter settings:

   ```sh
   OTEL_EXPORTER_OTLP_PROTOCOL="http/protobuf"
   OTEL_EXPORTER_OTLP_ENDPOINT="<OTLP_ENDPOINT>"
   OTEL_EXPORTER_OTLP_HEADERS="<OTLP_HEADERS>"
   ```

   Replace _`<OTLP_ENDPOINT>`_ and _`<OTLP_HEADERS>`_ with the values from [Send data to a backend](#send-data-to-a-backend).
   The unit fails to start if this file doesn't exist, so create it even if you set the exporters in `beyla.yaml`.

1. Download the unit file to `/etc/systemd/system/beyla.service`:

   ```sh
   sudo curl -L -o /etc/systemd/system/beyla.service https://raw.githubusercontent.com/grafana/beyla/main/contrib/beyla.service
   ```

1. Reload systemd, then start Beyla and turn it on at boot:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now beyla
   ```

1. Check that Beyla is running:

   ```sh
   systemctl status beyla
   ```

   To read the Beyla logs, run `journalctl -u beyla`.

## Next steps

- [Configure Beyla service discovery][service-discovery]
- [Configure Beyla Prometheus and OpenTelemetry data export][export-data]
- [Beyla security, permissions, and capabilities][security]
- [Run Beyla in a Docker container][docker]

[cloud-otlp]: https://grafana.com/docs/grafana-cloud/send-data/otlp/send-data-otlp/#manual-opentelemetry-setup-for-advanced-users
[docker]: ../docker/
[examples]: https://github.com/grafana/beyla/tree/main/examples/quickstart
[export-data]: ../../configure/export-data/
[releases]: https://github.com/grafana/beyla/releases
[requirements]: ../../requirements-and-security/requirements/
[security]: ../../requirements-and-security/security/
[service-discovery]: ../../configure/service-discovery/
[unit]: https://github.com/grafana/beyla/blob/main/contrib/beyla.service
