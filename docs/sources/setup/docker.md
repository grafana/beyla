---
title: Run Beyla in a Docker container
menuTitle: Docker
description: Run Grafana Beyla in a Docker container to instrument a service in another container, with the Docker CLI or Docker Compose.
weight: 200
keywords:
  - Beyla
  - eBPF
  - Docker
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/setup/docker/
---

# Run Beyla in a Docker container

You can run Grafana Beyla in its own Docker container to instrument a service that runs in another container.
Beyla shares the process ID (PID) namespace of the target container, so it finds and instruments the service process without changes to the service image.
The Beyla image is [`grafana/beyla`][docker-hub] on Docker Hub.

## Before you begin

Before you run Beyla in Docker, make sure you have the following:

- A Docker host with a Linux kernel that meets the [Beyla requirements and limitations][requirements]
- Docker, and Docker Compose if you use a Compose file
- A container that runs an HTTP, HTTPS, or gRPC service

## Container requirements

Beyla loads eBPF programs into the host kernel, so its container needs elevated privileges.
Run the container in privileged mode, or grant only the Linux capabilities Beyla needs for your use case.
For the list of capabilities, refer to [Beyla security, permissions, and capabilities][security].

Beyla also needs to see the process it instruments.
Share the PID namespace of the target container with the Beyla container.

{{< admonition type="note" >}}
If the Beyla container doesn't have the capabilities it needs, Beyla logs a warning and keeps running, but it might malfunction.
To stop Beyla at startup instead, set `BEYLA_ENFORCE_SYS_CAPS=true`.
{{< /admonition >}}

## Configure Beyla

The examples on this page configure Beyla with these environment variables:

| Environment variable  | Description                                                                                                                             |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `BEYLA_OPEN_PORT`     | Selects the process to instrument by the port it opens. Use the port inside the service container, not the port published on the host. |
| `BEYLA_TRACE_PRINTER` | Prints traces to standard output. `text` prints one line per request.                                                                   |

Beyla needs at least one exporter to start.
The trace printer counts as an exporter, so these examples run without a backend.

## Run Beyla

The examples instrument `mariomac/goblog:dev`, a blog engine written in Go.
It serves HTTPS on container port `8443`.
The examples publish that port on host port `18443`.
Replace `goblog` with the container you want to instrument.

{{< tabs >}}
{{< tab-content name="Docker CLI" >}}

1. Start the service container:

   ```sh
   docker run -p 18443:8443 --name goblog mariomac/goblog:dev
   ```

1. Run Beyla in privileged mode, in the PID namespace of the `goblog` container:

   ```sh
   docker run --rm \
     --privileged \
     --pid="container:goblog" \
     -e BEYLA_OPEN_PORT=8443 \
     -e BEYLA_TRACE_PRINTER=text \
     grafana/beyla:latest
   ```

{{< /tab-content >}}
{{< tab-content name="Docker Compose" >}}

1. Save the following as `compose-example.yml`:

   ```yaml
   version: "3.8"

   services:
     # Service to instrument. Replace it with the container you want to instrument.
     goblog:
       image: mariomac/goblog:dev
       ports:
         # Publishes container port 8443 on host port 18443
         - "18443:8443"

     beyla:
       image: grafana/beyla:latest
       pid: "service:goblog"
       privileged: true
       environment:
         BEYLA_TRACE_PRINTER: text
         BEYLA_OPEN_PORT: 8443
   ```

1. Start both services:

   ```sh
   docker compose -f compose-example.yml up
   ```

{{< /tab-content >}}
{{< /tabs >}}

## Verify that Beyla instruments the service

Open `https://localhost:18443` in your browser and use the app to generate requests.
Beyla prints a line for each request, similar to the following:

```text
2026-10-29 14:03:53.10292353 (19.066625ms[942.583µs]) HTTP(subType=0) 200 GET /(/) [172.17.0.1 as 172.17.0.1:52310]->[172.17.0.2 as 172.17.0.2:8443] contentLen:0B responseLen:5631B svc=[goblog go] traceparent=[00-0f82735dab5798dfbf7f7a26d5df827b-5d3c8e1f9a2b4c6d[0000000000000000]-01]
2026-10-29 14:03:53.10292353 (355.792µs[321.75µs]) HTTP(subType=0) 200 GET /static/style.css(/static/style.css) [172.17.0.1 as 172.17.0.1:52310]->[172.17.0.2 as 172.17.0.2:8443] contentLen:0B responseLen:2048B svc=[goblog go] traceparent=[00-1a2b3c4d5e6f708192a3b4c5d6e7f809-7e8f9a0b1c2d3e4f[0000000000000000]-01]
```

Addresses, timings, sizes, and IDs differ in your output.

## Send data to a backend

The trace printer is for testing.
To send data to a backend, replace `BEYLA_TRACE_PRINTER` with exporter settings.

To send metrics and traces to an OpenTelemetry endpoint, such as Grafana Cloud, set the OTLP environment variables:

```sh
docker run --rm \
  --privileged \
  --pid="container:<CONTAINER_NAME>" \
  -e BEYLA_OPEN_PORT=<SERVICE_PORT> \
  -e OTEL_EXPORTER_OTLP_PROTOCOL="http/protobuf" \
  -e OTEL_EXPORTER_OTLP_ENDPOINT="<OTLP_ENDPOINT>" \
  -e OTEL_EXPORTER_OTLP_HEADERS="<OTLP_HEADERS>" \
  grafana/beyla:latest
```

Replace the following:

- _`<CONTAINER_NAME>`_: The name of the container that runs the service to instrument
- _`<SERVICE_PORT>`_: The port the service opens inside its container
- _`<OTLP_ENDPOINT>`_: The URL of your OTLP endpoint
- _`<OTLP_HEADERS>`_: The headers your endpoint needs, such as authentication, as comma-separated `key=value` pairs

To expose metrics for Prometheus to scrape, set the Prometheus port and publish it from the Beyla container:

```sh
docker run --rm \
  --privileged \
  --pid="container:<CONTAINER_NAME>" \
  -p 9090:9090 \
  -e BEYLA_OPEN_PORT=<SERVICE_PORT> \
  -e BEYLA_PROMETHEUS_PORT=9090 \
  grafana/beyla:latest
```

Replace the following:

- _`<CONTAINER_NAME>`_: The name of the container that runs the service to instrument
- _`<SERVICE_PORT>`_: The port the service opens inside its container

Beyla serves the metrics at `http://localhost:9090/metrics`.

For all export options, refer to [Configure Beyla Prometheus and OpenTelemetry data export][export-data].

## Next steps

- [Configure Beyla Prometheus and OpenTelemetry data export][export-data]
- [Configure Beyla service discovery][service-discovery]
- [Beyla security, permissions, and capabilities][security]
- [Deploy Beyla in Kubernetes][kubernetes]

[docker-hub]: https://hub.docker.com/r/grafana/beyla
[requirements]: ../../introduction/requirements/
[security]: ../security/
[export-data]: ../../configure/export-data/
[service-discovery]: ../../configure/service-discovery/
[kubernetes]: ../kubernetes/
