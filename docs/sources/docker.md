---
title: Run as a Docker container
---
# Run as a Docker container

You can run the eBPF autoinstrumenter as a standalone Docker container that
instruments a process located in another container.

[Docker Hub](https://hub.docker.com/r/grafana/ebpf-autoinstrument) provides
an updated image of the eBPF autoinstrumenter, with the following image name:

```
grafana/ebpf-autoinstrument:latest
```

The autoinstrumenter container must be configured with the following properties:

* Run it either as a **privileged** container, or a container granted with the
  `SYS_ADMIN` capability.
* Share the PID space with the container that is going to be instrumented.

## CLI example

Let's start with an instrumentation example deployed via the Docker CLI.

First, you need a container running an HTTPS or GRPC service written in
Go. If you don't have any of them, you can use this [simple blog engine](http://macias.info):

```
docker run -p 18443:8443 --name goblog mariomac/goblog:dev
```

The above code will run a simple HTTPS application. The process opens the container's
internal port `8443`, and it is exposed to the host via the port `18443`.

First, let's check that the eBPF instrumenter is able to instrument the above
container. For that, we will configure it just to print each inspected trace
(environment `PRINT_TRACES=true`). We also instruct the autoinstrumenter to
inspect the executable that is opening the port `8443` (environment
`OPEN_PORT=8443`, please notice that it must refer to the container internal port).

In addition, the container needs some special privileges:

* Run in `--privileged` mode (alternatively, grant the `SYS_ADMIN` capability instead).
* Access to the above `goblog` container PID namespace (`--pid="container:goblog"`).

```
docker run --rm \
  -e OPEN_PORT=8443 \
  -e PRINT_TRACES=true \
  --pid="container:goblog" \
  --privileged \
  grafana/ebpf-autoinstrument:latest
```

Once it is running, you can do some requests to `https://localhost:8443` and
verify that the autoinstrumenter standard output prints the traced requests:

```
time=2023-05-22T14:03:42.402Z level=INFO msg="creating instrumentation pipeline"
time=2023-05-22T14:03:42.526Z level=INFO msg="Starting main node"
2023-05-22 14:03:53.5222353 (19.066625ms[942.583µs]) 200 GET / [172.17.0.1]->[localhost:18443] size:0B
2023-05-22 14:03:53.5222353 (355.792µs[321.75µs]) 200 GET /static/style.css [172.17.0.1]->[localhost:18443] size:0B
2023-05-22 14:03:53.5222353 (170.958µs[142.916µs]) 200 GET /static/img.png [172.17.0.1]->[localhost:18443] size:0B
2023-05-22 14:13:47.52221347 (7.243667ms[295.292µs]) 200 GET /entry/201710281345_instructions.md [172.17.0.1]->[localhost:18443] size:0B
2023-05-22 14:13:47.52221347 (115µs[75.625µs]) 200 GET /static/style.css [172.17.0.1]->[localhost:18443] size:0B
```

Once we verify that the auto-instrumenter is properly tracing the target HTTP services,
you can configure it to send information to an OpenTelemetry or Prometheus endpoint.
You can check the [Quick tutorial]({{< relref "./tutorial" >}}) and the [Configuration]({{< relref "./config" >}})
sections of this documentation site.

## Docker Compose example

The following Docker compose example file provides an
alternative that is analogue to the example in the previous section.

```yaml
version: '3.8'

services:
  # Service to instrument. Change it by any
  # other container at your convenience
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
    # if the above section fails, just remove it
    # and uncomment the line below
    # privileged: true
    environment:
      PRINT_TRACES: true
      OPEN_PORT: 8443
```

You can run it via:

```
docker compose -f compose-example.yml up
```

If you navigate a bit through `https://localhost:8443`, wou will see the logs of
both the instrumented service and the auto-instrumenter:

```
docs-goblog-1            | time="2023-05-22T14:42:50Z" level=debug msg="new request" component=assets/handler.go method=GET remoteAddr="172.18.0.1:35488" url=/entry/201710281345_instructions.md
docs-goblog-1            | time="2023-05-22T14:42:50Z" level=debug msg="new request" component=assets/handler.go method=GET remoteAddr="172.18.0.1:35488" url=/static/style.css
docs-autoinstrumenter-1  | 2023-05-22 14:42:50.52224250 (7.617792ms[867.667µs]) 200 GET /entry/201710281345_instructions.md [172.18.0.1]->[localhost:18443] size:0B
docs-autoinstrumenter-1  | 2023-05-22 14:42:50.52224250 (613.791µs[547.041µs]) 200 GET /static/style.css [172.18.0.1]->[localhost:18443] size:0B
```
