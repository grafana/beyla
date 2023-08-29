---
title: Run as a Docker container
menuTitle: Docker
description: Learn how to run Grafana's eBPF auto-instrumentation tool as a standalone Docker container, which instruments another container.
weight: 2
---

# Run as a Docker container

You can run Beyla - the eBPF auto-instrumentation tool as a standalone Docker container,
which instruments a process running in another container.

[Docker Hub](https://hub.docker.com/r/grafana/ebpf-autoinstrument) provides
an updated image of the eBPF auto-instrumentation tool, with the following image name:

```
grafana/ebpf-autoinstrument:latest
```

The auto-instrument container must be configured with the following properties:

* It must be run either as a **privileged** container, or as a container with the
  `SYS_ADMIN` capability.
* It must share the PID space with the container that is being instrumented.

## Docker command line interface (CLI) example

Let's start with an instrumentation example by using the Docker CLI.

First, you'll need a container running an HTTP/S or GRPC service.
If you don't have one handy, you can use this [simple blog engine service written in Go](http://macias.info):

```sh
docker run -p 18443:8443 --name goblog mariomac/goblog:dev
```

The above command line will run a simple HTTPS application. The process opens the container's
internal port `8443`, which is then exposed at the host level as the port `18443`.

Next, let's check that Beyla is able to auto-instrument the above
container. Initially, we will configure Beyla to simply print (on stdout) each collected trace event,
by setting the environment variable `PRINT_TRACES=true`. We will also instruct the tool to
inspect the executable that is listening on port `8443`, by setting the environment variable
`OPEN_PORT=8443`. Please note that we are using the application container's internal port `8443`, and
not the port visible at the host level.

To run properly, the auto-instrument container needs some special settings. Namely:

* We'll run in `--privileged` mode (or alternatively, we can grant it the `SYS_ADMIN` capability).
* We'll let it access the `goblog` container PID namespace, by using the command line option `--pid="container:goblog"`.

```sh
docker run --rm \
  -e OPEN_PORT=8443 \
  -e PRINT_TRACES=true \
  --pid="container:goblog" \
  --privileged \
  grafana/ebpf-autoinstrument:latest
```

Once Beyla's (the auto-instrument tool) container is running, you can open `https://localhost:8443` in your browser,
click around a bit, and verify that the auto-instrument tool prints some traced requests on stdout. For example,
the standard output (stdout) might look like this:

```sh
time=2023-05-22T14:03:42.402Z level=INFO msg="creating instrumentation pipeline"
time=2023-05-22T14:03:42.526Z level=INFO msg="Starting main node"
2023-05-22 14:03:53.5222353 (19.066625ms[942.583µs]) 200 GET / [172.17.0.1]->[localhost:18443] size:0B
2023-05-22 14:03:53.5222353 (355.792µs[321.75µs]) 200 GET /static/style.css [172.17.0.1]->[localhost:18443] size:0B
2023-05-22 14:03:53.5222353 (170.958µs[142.916µs]) 200 GET /static/img.png [172.17.0.1]->[localhost:18443] size:0B
2023-05-22 14:13:47.52221347 (7.243667ms[295.292µs]) 200 GET /entry/201710281345_instructions.md [172.17.0.1]->[localhost:18443] size:0B
2023-05-22 14:13:47.52221347 (115µs[75.625µs]) 200 GET /static/style.css [172.17.0.1]->[localhost:18443] size:0B
```

Now that we have verified that the auto-instrumentation tool is properly tracing the target HTTP service,
you can configure it to send metrics and traces to an OpenTelemetry endpoint, or have metrics scraped by Prometheus.
For information on how to export traces and metrics, you can check the [quick start tutorial]({{< relref "../tutorial/index.md" >}})
and the [Configuration]({{< relref "../configure/options.md" >}}) sections of this documentation site.

## Docker Compose example

The following Docker compose example file does the same as the Docker CLI section above,
but through a single compose file.

```yaml
version: '3.8'

services:
  # Service to instrument. Change it to any
  # other container that you want to instrument.
  goblog:
    image: mariomac/goblog:dev
    ports:
      # Exposes port 18843, forwarding it to container port 8443
      - "18443:8443"

  autoinstrumenter:
    image: grafana/ebpf-autoinstrument:latest
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

You can run the above Docker compose file via the following command line:

```sh
docker compose -f compose-example.yml up
```

If you navigate a bit through `https://localhost:8443`, wou will see the logs of
both the instrumented service and the auto-instrument tool:

```sh
docs-goblog-1            | time="2023-05-22T14:42:50Z" level=debug msg="new request" component=assets/handler.go method=GET remoteAddr="172.18.0.1:35488" url=/entry/201710281345_instructions.md
docs-goblog-1            | time="2023-05-22T14:42:50Z" level=debug msg="new request" component=assets/handler.go method=GET remoteAddr="172.18.0.1:35488" url=/static/style.css
docs-autoinstrumenter-1  | 2023-05-22 14:42:50.52224250 (7.617792ms[867.667µs]) 200 GET /entry/201710281345_instructions.md [172.18.0.1]->[localhost:18443] size:0B
docs-autoinstrumenter-1  | 2023-05-22 14:42:50.52224250 (613.791µs[547.041µs]) 200 GET /static/style.css [172.18.0.1]->[localhost:18443] size:0B
```
