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

## 1. Run your instrumentable Go service

You can use any Go service of your own. For testing purposes, you can also download and run this
[simple Go HTTP service](https://github.com/grafana/beyla/tree/main/examples/quickstart/golang).

```
curl -OL https://raw.githubusercontent.com/grafana/beyla/main/examples/quickstart/golang/quickstart.go
go run quickstart.go
```

## 2. Download Beyla

You can download the latest Beyla executable from the [Beyla releases page](https://github.com/grafana/beyla/releases).
Uncompress and copy the Beyla executable to any location in your `$PATH`.

As an alternative (if your host has the Go toolset installed), you can directly download the
Beyla executable with the `go install` command:

```sh
go install github.com/grafana/beyla/cmd/beyla@latest
```

## 3. (Optional) get your Grafana Cloud credentials

Beyla can export metrics and traces to any OpenTelemetry endpoint, as well as exposing
metrics as a Prometheus endpoint. However, we recommend using the OpenTelemetry
endpoint in Grafana Cloud. You can get a [Free Grafana Cloud Account at Grafana's website](/pricing/).

In your Grafana Cloud Portal, click on the "Details" button in the "OpenTelemetry" box. Next,
copy your Grafana OTLP Endpoint and Instance ID, as in the image below.

![](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/otlp-connection-details.png)

Also generate a Password/API token with metrics push privileges.

## 4. Run Beyla with minimal configuration

To run Beyla, you will require to set the following environment variables:

* `BEYLA_OPEN_PORT`: the port where your instrumented service is listening
  (for example, `80` or `443`). If you are using the example service in the
  first section of this guide, you need to set this variable to `8080`.
* `OTEL_EXPORTER_OTLP_ENDPOINT`: the OpenTelemetry endpoint URL, as obtained
  in the previous section (for example: `https://otlp-gateway-prod-eu-west-0.grafana.net/otlp`)
* `GRAFANA_CLOUD_INSTANCE_ID`: the Grafana Cloud Username / Instance ID, as
  obtained in the previous section.
* `GRAFANA_CLOUD_API_KEY`: your Grafana Cloud API Key.

To facilitate local testing, we will also set the `BEYLA_PRINT_TRACES=true` environment
variable. This will print the traces of your instrumented service in the standard output
of Beyla.

Please notice that Beyla requires to run with administrative privileges.

```sh
export OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp-gateway-prod-eu-west-0.grafana.net/otlp
export GRAFANA_CLOUD_INSTANCE_ID=123456
export GRAFANA_CLOUD_API_KEY="your api key here..."
export BEYLA_OPEN_PORT=8080
export BEYLA_PRINT_TRACES=true

sudo -E beyla
```

## 5. Test your service

Having either your service running (step 1) and Beyla running (step 4), you can do
some HTTP requests to the instrumented service. For example:

```
curl http://localhost:8080/foo
```

In the Beyla standard output, you will see the information of the intercepted trace:

```
2024-01-08 14:06:14.182614 (432.191µs[80.421µs]) 200 GET /foo [127.0.0.1]->[localhost:8080]
size:0B svc=[{quickstart  go lima-ubuntu-lts-8222}] traceparent=[00-0f82735dab5798dfbf7f7a26d5df827b-0000000000000000-01]
```

The above trace shows, in the following order:

* `2024-01-08 14:06:14.182614`: time of the trace.
* `(432.191µs[80.421µs])`: total response time for the request, with the actual internal execution
  time of the request (not counting the request enqueuing time).
* `200 GET /foo`: response code, HTTP method, and URL path.
* `[127.0.0.1]->[localhost:8080]` source and destination host:port.
* `size:0B`: size of the HTTP request body (0 bytes, as it was a `GET` request).
  For non-go programs, this size would also include the size of the request headers.
* `svc=[{quickstart  go lima-ubuntu-lts-8222}]`: `quickstart` service, written
  in Go, with an automatically created service instance name `lima-ubuntu-lts-8222`.
* `traceparent=[00-0f82735dab5798dfbf7f7a26d5df827b-0000000000000000-01]` as used for distributed
  tracing.

If your Grafana Cloud credentials were properly set, you should see the trace also
in Grafana Cloud. For example, in the traces explorer:

![](https://grafana.com/media/docs/grafana-cloud/beyla/quickstart/trace.png)

## 6. Configure routing

In the previous step, you might have realized that the exposed span name in Grafana Cloud
is a generic `GET /**`, where it should say something like `GET /foo` (the path of the
test request URL).

To avoid unexpected cardinality explosions, Beyla groups any unknown URL path as `/**` but
we can provide Beyla with some hints about the expected paths.

For this quickstart, we will let Beyla to heuristically group the routes.

First, create a `config.yml` file with the following content:

```yml
routes:
  unmatched: heuristic
```

And now run Beyla with the `-config` argument:

```
sudo -E beyla -config config.yml
```

And do some HTTP request calls:

```
curl http://localhost:8080/foo
curl http://localhost:8080/user/1234
curl http://localhost:8080/user/5678
```

If you search for the new traces in Grafana, you will see how Beyla heuristically
assigned a route to each trace. `/foo` got its own route while `/user/1234` and
`/user/5678` were grouped into the `/user/*` route.

![](https://grafana.com/media/docs/grafana-cloud/beyla/quickstart/grouped-traces.png)

## Where to continue

* Get more details of the different [Beyla configuration options]({{< relref "../configure" >}}).
* Learn how to deploy Beyla as a [Docker container]({{< relref "../setup/docker.md" >}}) or as a
  [Kubernetes DaemonSet or sidecar]({{< relref "../setup/kubernetes.md" >}}).


