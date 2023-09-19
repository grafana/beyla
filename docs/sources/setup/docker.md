---
title: Run Beyla as a Docker container
menuTitle: Docker
description: Learn how to set up and run Beyla as a standalone Docker container that instruments another container.
weight: 2
keywords:
  - Beyla
  - eBPF
  - Docker
---

# Run Beyla as a Docker container

Beyla can run a standalone Docker container that can instrument a process running in another container.

Find the latest image of Beyla on [Docker Hub](https://hub.docker.com/r/grafana/beyla) with the following name:

```
grafana/beyla:latest
```

The Beyla container must be configured in following way:

- run as a **privileged** container, or as a container with the `SYS_ADMIN` capability
- share the PID space with the container that is being instrumented

## Docker CLI example

For this example you need a container running an HTTP/S or GRPC service. If you don't have one, you can use this [simple blog engine service written in Go](http://macias.info):

```sh
docker run -p 18443:8443 --name goblog mariomac/goblog:dev
```

The above command runs a simple HTTPS application. The process opens the container's internal port `8443`, which is then exposed at the host level as the port `18443`.

Set environment variables to configure Beyla to print to stdout and listen to a port (container) to inspect the executable:

```sh
export PRINT_TRACES=true
export OPEN_PORT=8443
```

Beyla needs to be run with the following settings:

- in `--privileged` mode, or with `SYS_ADMIN` capability
- a container PID namespace, with the option `--pid="container:goblog"`.

```sh
docker run --rm \
  -e OPEN_PORT=8443 \
  -e PRINT_TRACES=true \
  --pid="container:goblog" \
  --privileged \
  grafana/beyla:latest
```

Once Beyla is running, open `https://localhost:8443` in your browser, use the app to generate test data, and verify that Beyla prints trace requests to stdout similar to:

```sh
time=2023-05-22T14:03:42.402Z level=INFO msg="creating instrumentation pipeline"
time=2023-05-22T14:03:42.526Z level=INFO msg="Starting main node"
2023-05-22 14:03:53.5222353 (19.066625ms[942.583µs]) 200 GET / [172.17.0.1]->[localhost:18443] size:0B
2023-05-22 14:03:53.5222353 (355.792µs[321.75µs]) 200 GET /static/style.css [172.17.0.1]->[localhost:18443] size:0B
2023-05-22 14:03:53.5222353 (170.958µs[142.916µs]) 200 GET /static/img.png [172.17.0.1]->[localhost:18443] size:0B
2023-05-22 14:13:47.52221347 (7.243667ms[295.292µs]) 200 GET /entry/201710281345_instructions.md [172.17.0.1]->[localhost:18443] size:0B
2023-05-22 14:13:47.52221347 (115µs[75.625µs]) 200 GET /static/style.css [172.17.0.1]->[localhost:18443] size:0B
```

Now that Beyla is tracing the the target HTTP service, configure it to send metrics and traces to an OpenTelemetry endpoint, or have metrics scraped by Prometheus.

For information on how to export traces and metrics, see the [quick start tutorial]({{< relref "../tutorial/index.md" >}}) and the [configuration options]({{< relref "../configure/options.md" >}}) documentation.

## Docker Compose example

The following Docker compose file replicates the same functionality of the Docker CLI example:

```yaml
version: "3.8"

services:
  # Service to instrument. Change it to any
  # other container that you want to instrument.
  goblog:
    image: mariomac/goblog:dev
    ports:
      # Exposes port 18843, forwarding it to container port 8443
      - "18443:8443"

  autoinstrumenter:
    image: grafana/beyla:latest
    pid: "service:goblog"
    cap_add:
      - SYS_ADMIN
    # If using the above capability fails to instrument your service, remove it
    # and uncomment the line below
    # privileged: true
    environment:
      PRINT_TRACES: true
      OPEN_PORT: 8443
```

Run the Docker compose file with the following command and use the app to generate traces:

```sh
docker compose -f compose-example.yml up
```
