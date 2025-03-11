---
title: "Quickstart: instrument a Go service with Beyla"
menuTitle: Go quickstart
description: Learn how to quickly set up and run Beyla to instrument a Go service
weight: 2
keywords:
  - Beyla
  - eBPF
  - Go
  - Golang
---

# Quickstart: instrument a Go service with Beyla

## 1. Run an instrumentable Go service

Run an instrumentable Go service or download and run a simple example [Go HTTP service](https://github.com/grafana/beyla/tree/main/examples/quickstart/golang).

```
curl -OL https://raw.githubusercontent.com/grafana/beyla/main/examples/quickstart/golang/quickstart.go
go run quickstart.go
```

## 2. Download Beyla

Download the latest Beyla executable from the [Beyla releases page](https://github.com/grafana/beyla/releases).
Uncompress and copy the Beyla executable to any location in your `$PATH`.

As an alternative (if your host has the Go toolset installed), you can directly download the
Beyla executable with the `go install` command:

```sh
go install github.com/grafana/beyla/cmd/beyla@latest
```

## 3. (Optional) get Grafana Cloud credentials

Beyla can export metrics and traces to any OpenTelemetry endpoint, as well as exposing metrics as a Prometheus endpoint. However, we recommend using the OpenTelemetry endpoint in Grafana Cloud. You can get a [Free Grafana Cloud Account at Grafana's website](/pricing/).

From the Grafana Cloud Portal, look for the **OpenTelemetry** box and click **Configure**.

![OpenTelemetry Grafana Cloud portal](https://grafana.com/media/docs/grafana-cloud/beyla/quickstart/otel-cloud-portal-box.png)

Under **Password / API token** click **Generate now** and follow the instructions to create a default API token.

The **Environment Variables** will be populated with a set of standard OpenTelemetry environment variables which will provide the connection endpoint and credentials information for Beyla.

![OTLP connection headers](https://grafana.com/media/docs/grafana-cloud/beyla/quickstart/otlp-connection-headers.png)

Copy the **Environment Variables** and keep it for the next step.

## 4. Run Beyla with minimal configuration

To run Beyla, first set the following environment variables:

- The `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_EXPORTER_OTLP_HEADERS`
  variables copied from the previous step.
- `BEYLA_OPEN_PORT`: the port the instrumented service is using
  (for example, `80` or `443`). If using the example service in the
  first section of this guide, set this variable to `8080`.

To facilitate local testing, set the `BEYLA_TRACE_PRINTER=text` environment variable. When this option is set, Beyla prints traces in text format to the standard output.

Notice: Beyla requires administrative (sudo) privileges, or at least it needs to be granted the `CAP_SYS_ADMIN` capability.

```sh
export BEYLA_OPEN_PORT=8080
export BEYLA_TRACE_PRINTER=text
export OTEL_EXPORTER_OTLP_PROTOCOL="http/protobuf"
export OTEL_EXPORTER_OTLP_ENDPOINT="https://otlp-gateway-prod-eu-west-0.grafana.net/otlp"
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic ...your-encoded-credentials..."
sudo -E beyla
```

## 5. Test the service

With Beyla and the service running, make HTTP requests to the instrumented service:

```
curl http://localhost:8080/foo
```

Beyla should output traces to the standard output similar to this:

```
2024-01-08 14:06:14.182614 (432.191µs[80.421µs]) 200 GET /foo [127.0.0.1]->[localhost:8080]
size:0B svc=[{quickstart  go lima-ubuntu-lts-8222}] traceparent=[00-0f82735dab5798dfbf7f7a26d5df827b-0000000000000000-01]
```

The above trace shows:

- `2024-01-08 14:06:14.182614`: time of the trace
- `(432.191µs[80.421µs])`: total response time for the request, with the actual internal execution
  time of the request (not counting the request enqueuing time)
- `200 GET /foo`: response code, HTTP method, and URL path
- `[127.0.0.1]->[localhost:8080]` source and destination host:port
- `size:0B`: size of the HTTP request body (0 bytes, as it was a `GET` request).
  For non-go programs, this size would also include the size of the request headers
- `svc=[{quickstart  go lima-ubuntu-lts-8222}]`: `quickstart` service, written
  in Go, with an automatically created service instance name `lima-ubuntu-lts-8222`
- `traceparent` as received by the parent request, or a new random one if the parent request didn't specify it

After a few minutes traces will appear in Grafana Cloud. For example, in the traces explorer:

![Beyla traces explorer](https://grafana.com/media/docs/grafana-cloud/beyla/quickstart/trace.png)

## 6. Configure routing

The exposed span name in Grafana Cloud is a generic `GET /**`, where it should say something like `GET /foo` (the path of the
test request URL).

Beyla groups any unknown URL path as `/**` to avoid unexpected cardinality explosions.

Configure routing to tell Beyla about expected routes.

For this quickstart, let Beyla to heuristically group the routes.

First, create a `config.yml` file with the following content:

```yml
routes:
  unmatched: heuristic
```

Then, run Beyla with the `-config` argument (or use the `BEYLA_CONFIG_PATH` environment variable instead):

```
sudo -E beyla -config config.yml
```

Finally, make HTTP requests:

```
curl http://localhost:8080/foo
curl http://localhost:8080/user/1234
curl http://localhost:8080/user/5678
```

Grafana will now heuristically assign a route to each trace. `/foo` got its own route while `/user/1234` and
`/user/5678` were grouped into the `/user/*` route.

![Beyla grouped traces](https://grafana.com/media/docs/grafana-cloud/beyla/quickstart/grouped-traces.png)

## Next steps

- Get more details of the different [Beyla configuration options](../../configure/).
- Learn how to deploy Beyla as a [Docker container](../../setup/docker/) or as a [Kubernetes DaemonSet or sidecar](../../setup/kubernetes/).
