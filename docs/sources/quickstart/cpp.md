---
title: "Quickstart: instrument a C/C++ service with Beyla"
menuTitle: C/C++ quickstart
description: Learn how to quickly set up and run Beyla to instrument a C/C++ service
weight: 2
keywords:
  - Beyla
  - eBPF
  - C
  - C++
---

# Quickstart: instrument a C/C++ service with Beyla

## 1. Run your instrumentable C/C++ service

You can use any service of your own. For testing purposes, you can also download and run this
[simple C++ HTTP service](https://github.com/grafana/beyla/tree/main/examples/quickstart/cpp).

```
curl -OL https://raw.githubusercontent.com/grafana/beyla/main/examples/quickstart/cpp/httplib.h
curl -OL https://raw.githubusercontent.com/grafana/beyla/main/examples/quickstart/cpp/quickstart.cpp
g++ -std=c++11 quickstart.cpp -o quickstart && ./quickstart
```

You can replace the `g++` command by another compiler supporting C++11.

## 2. Download Beyla

You can download the latest Beyla executable from the [Beyla releases page](https://github.com/grafana/beyla/releases).
Uncompress and copy the Beyla executable to any location in your `$PATH`.

## 3. (Optional) get your Grafana Cloud credentials

Beyla can export metrics and traces to any OpenTelemetry endpoint, as well as exposing
metrics as a Prometheus endpoint. However, we recommend using the OpenTelemetry
endpoint in Grafana Cloud. You can get a [Free Grafana Cloud Account at Grafana's website](/pricing/).

In your Grafana Cloud Portal, look for the "OpenTelemetry box" and push the "Configure" button.

![](https://grafana.com/media/docs/grafana-cloud/beyla/quickstart/otel-cloud-portal-box.png)

Once there, you will see a section titled "Password / API token". Click into "Generate now"
and follow the instructions to create a default API token. Then a section named "Environment
Variables" is populated with a set of standard OpenTelemetry environment variables which will
provide the connection endpoint and credentials information for Beyla.

![](https://grafana.com/media/docs/grafana-cloud/beyla/quickstart/otlp-connection-headers.png)

You need to copy the content of the Environment Variables box and keep it for the next step.

## 4. Run Beyla with minimal configuration

To run Beyla, you will require to set the following environment variables:

* The `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_EXPORTER_OTLP_HEADERS`
  variables copied from the previous step.
* `BEYLA_OPEN_PORT`: the port where your instrumented service is listening
  (for example, `80` or `443`). If you are using the example service in the
  first section of this guide, you need to set this variable to `8080`.

To facilitate local testing, we will also set the `BEYLA_PRINT_TRACES=true` environment
variable. This will print the traces of your instrumented service in the standard output
of Beyla.

Notice that Beyla requires to run with administrative privileges.

```sh
export BEYLA_OPEN_PORT=8080
export BEYLA_PRINT_TRACES=true
export OTEL_EXPORTER_OTLP_PROTOCOL="http/protobuf"
export OTEL_EXPORTER_OTLP_ENDPOINT="https://otlp-gateway-prod-eu-west-0.grafana.net/otlp"
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic ...your-encoded-credentials..."
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
2024-01-09 10:31:33.19103133 (3.254486ms[3.254486ms]) 200 GET /foo [127.0.0.1]->[127.0.0.1:8080]
size:80B svc=[{quickstart  generic lima-ubuntu-lts-5074}] traceparent=[00-46214bd23716280eef43cf798dbe5522-0000000000000000-01]
```

The above trace shows, in the following order:

* `2024-01-09 10:31:33.19103133`: time of the trace.
* `(3.254486ms[3.254486ms])`: total response time for the request.
* `200 GET /foo`: response code, HTTP method, and URL path.
* `[127.0.0.1]->[127.0.0.1:8080]` source and destination host:port.
* `size:80B`: size of the HTTP request (sum of the headers and the body).
* `svc=[{quickstart  generic lima-ubuntu-lts-5074}]`: `quickstart` service, using the
  generic kernel-based instrumenter, with an automatically created service instance name
  `lima-ubuntu-lts-5074`.
* `traceparent` as received by the parent request, or a new random one if the parent request
  didn't specify it.

If your Grafana Cloud credentials were properly set, you should see the trace also
in Grafana Cloud. For example, in the traces explorer:

![](https://grafana.com/media/docs/grafana-cloud/beyla/quickstart/trace-generic.png)

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


