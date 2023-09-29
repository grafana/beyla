---
title: Beyla quick start tutorial
menuTitle: Quick start tutorial
description: Learn how to instrument an application export data with Prometheus to Grafana Cloud.
weight: 3
keywords:
  - Beyla
  - eBPF
  - Prometheus
  - Grafana Cloud
  - tutorial
  - RED metrics
---

![Grafana Beyla Logo](https://grafana.com/media/docs/grafana-cloud/beyla/beyla-logo-2.png)

# Beyla quick start tutorial

To reduce the time it takes to instrument an application and improve the adoption of Application Observability, Grafana built Beyla, an eBPF auto-instrumentation tool, that is able to report basic transactions span information, as well as [RED metrics](/blog/2018/08/02/the-red-method-how-to-instrument-your-services/) for Linux HTTP/S and gRPC services, without any application code or configuration changes.

## eBPF overview

eBPF stands for Extended Berkeley Packet Filter, and allows attaching applications to different points of the Linux Kernel. eBPF applications run in privileged mode and allow the runtime information of the Linux Kernel to be inspected: system calls, network stack, as well as inserting probes in user space applications.

The eBPF applications are safe, they are compiled for their own [Virtual Machine instruction set](https://docs.kernel.org/bpf/instruction-set.html) and run in a sandboxed environment that verifies each loaded eBPF program for memory access safety and finite execution time. Unlike older technologies, such as the natively-compiled Kprobes and Uprobes, there is no chance that a poorly programmed probe will cause the Linux Kernel to hang.

After being the eBPF binaries have been verified they are compiled with a Just-In-Time (JIT) compiler for the native host architecture (x86-64, ARM64, etc). This allows for efficient and fast execution.

The eBPF code is loaded from ordinary applications running in user space. The kernel and the user space applications can share information through a set of well defined communication mechanisms, which are provided by the eBPF specification. For example: ring buffers, arrays, hash maps, etc.

![](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/ebpf-arch.svg)

## Running an instrumented service

For this quick start tutorial, instrument any HTTP, HTTPS or gRPC Go service that uses any of the following libraries:

- Standard `net/http`
- [Gorilla Mux](https://github.com/gorilla/mux)
- [Gin](https://gin-gonic.com/)
- [gRPC-Go](https://github.com/grpc/grpc-go)

HTTP and HTTPS services written in other languages can also be instrumented:

- Node.js (HTTP 1.1 and HTTPS with OpenSSL)
- Python (HTTP 1.1 and HTTPS with OpenSSL)
- Rust (HTTP 1.1 and HTTPS with OpenSSL)
- Ruby (HTTP 1.1 and HTTPS with OpenSSL)
- .NET Core 6+ (HTTP 1.1 and HTTPS with OpenSSL)
- Java (HTTP 1.1)

The HTTP 1.1 and OpenSSL support is generic, services written in different programming languages than those listed above might work, but haven't been tested.

If you don't have a service to instrument, create a `server.go` file with the following code:

```go
package main

import (
	"net/http"
	"strconv"
	"time"
)

func handleRequest(rw http.ResponseWriter, req *http.Request) {
	status := 200
	for k, v := range req.URL.Query() {
		if len(v) == 0 {
			continue
		}
		switch k {
		case "status":
			if s, err := strconv.Atoi(v[0]); err == nil {
				status = s
			}
		case "delay":
			if d, err := time.ParseDuration(v[0]); err == nil {
				time.Sleep(d)
			}
		}
	}
	rw.WriteHeader(status)
}

func main() {
	http.ListenAndServe(":8080", http.HandlerFunc(handleRequest))
}
```

The code implements an HTTP service that accepts request on port 8080. The HTTP handler behavior can be specified with the following query parameters:

- `status` will override the returned HTTP status code (which defaults to 200). For example `curl -v "http://localhost:8080/foo?status=404"` will return a 404 status code.
- `delay` will artificially increase the service response time. For example `curl "http://localhost:8080/bar?delay=3s"` will take at least 3 seconds to complete.

Download the [server.go](/docs/grafana-cloud/monitor-applications/beyla/tutorial/resources/server.go) file from this tutorial.

Run the test HTTP service with the following command:

```sh
go run server.go
```

## Instrument a service

Set up Beyla as a standalone linux process by following the [standalone setup]({{< relref "../setup/standalone.md" >}}) documentation.

Metrics will be exported from a [Prometheus](https://prometheus.io/) scrape endpoint by setting the `BEYLA_PROMETHEUS_PORT` environment variable. Traces will be printed to stdout by setting the `PRINT_TRACES=true` environment variable.

For information on how to configure other exporters like [OpenTelemetry](https://opentelemetry.io/), see the
[configuration options]({{< relref "../configure/options.md" >}}) documentation.

Set environment variables and run Beyla:

```sh
BEYLA_PROMETHEUS_PORT=8999 PRINT_TRACES=true OPEN_PORT=8080 sudo -E beyla
```

Open a new terminal and send a few HTTP GET calls to the test service:

```sh
curl "http://localhost:8080/hello"
curl "http://localhost:8080/bye"
```

Beyla will log trace information to the first terminal:

```sh
2023-04-19 13:49:04 (15.22ms[689.9µs]) 200 GET /hello [::1]->[localhost:8080] size:0B
2023-04-19 13:49:07 (2.74ms[135.9µs]) 200 GET /bye [::1]->[localhost:8080] size:0B
```

The output format is:

```
Request_time (response_duration) status_code http_method path source->destination request_size
```

Experiment with the `curl` command and make additional requests to see how it affects the trace output. For example, the following request would send a 6-bytes POST request and the service will take 200ms to respond:

```sh
curl -X POST -d "abcdef" "http://localhost:8080/post?delay=200ms"
```

Beyla will log the following trace information:

```sh
2023-04-19 15:17:54 (210.91ms[203.28ms]) 200 POST /post [::1]->[localhost:8080] size:6B
```

Optionally, open another terminal and run the following command to generate some artificial load:

```sh
while true; do curl "http://localhost:8080/service?delay=1s"; done
```

Next, query the Prometheus metrics exposed on port `8999`:

```sh
curl http://localhost:8999/metrics
```

Which will output a result similar to:

```sh
# HELP http_server_duration_seconds duration of HTTP service calls from the server side, in milliseconds
# TYPE http_server_duration_seconds histogram
http_server_duration_seconds_bucket{http_method="GET",http_status_code="200",service_name="testserver",le="0.005"} 1
http_server_duration_seconds_bucket{http_method="GET",http_status_code="200",service_name="testserver",le="0.005"} 1
http_server_duration_seconds_bucket{http_method="GET",http_status_code="200",service_name="testserver",le="0.01"} 1

(... output snipped for sake of brevity ...)
```

For information on the metrics Beyla exports, see the [exported metrics]({{< relref "../metrics.md" >}}) documentation.

## Send data to Grafana Cloud

Once we have verified that our application is correctly instrumented, we can add a Prometheus
collector to read the generated metrics and forward them to Grafana Cloud.
You can get a [Free Grafana Cloud Account at Grafana's website](/pricing/).

There are two ways to forward your metrics to Grafana Cloud:

- [Install Prometheus on your host, configure the scrape and remote write to read-and-forward the metrics
  ](/docs/grafana-cloud/quickstart/noagent_linuxnode/#install-prometheus-on-the-node)
- Use the [Grafana Agent](/docs/agent/latest/), as shown by this tutorial.

### Downloading and configuring the Grafana Agent Flow

> ⚠️ This section explains how to download and configure the Grafana Agent Flow manually.
> For a complete description of the Grafana Agent Flow setup, its configuration process,
> and the recommended modes, please refer to the [Install Grafana Agent Flow](/docs/agent/latest/flow/setup/install/)
> documentation.

1. Go to the [Grafana Agent Releases page](https://github.com/grafana/agent/releases/).
2. Choose the latest version for your system architecture.
   - For example, we are downloading zipped 0.34.3 version for Linux Intel/AMD 64-bit architecture:
     ```
     $ wget https://github.com/grafana/agent/releases/download/v0.34.3/grafana-agent-linux-amd64.zip
     $ unzip grafana-agent-linux-amd64.zip
     ```
3. Create a plain text file named `ebpf-tutorial.river` and paste the
   following text:

   ```
   prometheus.scrape "default" {
       targets = [{"__address__" = "localhost:8999"}]
       forward_to = [prometheus.remote_write.mimir.receiver]
   }
   prometheus.remote_write "mimir" {
       endpoint {
           url = env("MIMIR_ENDPOINT")
           basic_auth {
               username = env("MIMIR_USER")
               password = env("GRAFANA_API_KEY")
           }
       }
   }
   ```

The configuration file instructs the Agent to scrape Prometheus metrics, from Beyla and forward them to [Grafana Mimir](/oss/mimir/).

Note that we configured the Agent to scrape the metrics from the `localhost:8999` address,
same as the value of the `BEYLA_PROMETHEUS_PORT` variable from the previous section.
At the same time, the connection details and the authentication credentials for Grafana Mimir are
to be provided via environment variables.

### Running the Grafana Agent Flow with your Grafana Credentials

In your Grafana Cloud Portal, click on the "Details" button in the "Prometheus" box. Next,
copy your Grafana Prometheus (Mimir) Remote Write endpoint, your username, and generate/copy
a Grafana API Key with metrics push privileges:

![](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/grafana-instance-id.png)

Now you can run the Agent by using the above information to set the
`MIMIR_ENDPOINT`, `MIMIR_USER` and `GRAFANA_API_KEY` environment variables. For example:

```sh
export MIMIR_ENDPOINT="https://prometheus-prod-01-eu-west-0.grafana.net/api/prom/push"
export MIMIR_USER="123456"
export GRAFANA_API_KEY="your api key here"
AGENT_MODE=flow ./grafana-agent-linux-amd64 run ebpf-tutorial.river

ts=2023-06-29T08:02:58.761420514Z level=info msg="now listening for http traffic" addr=127.0.0.1:12345
ts=2023-06-29T08:02:58.761546307Z level=info trace_id=359c08a12e833f29bf21457d95c09a08 msg="starting complete graph evaluation"
(more logs....)
```

To verify that metrics are properly received by Grafana, you can go to the left panel,
choose the Explore tab and your Prometheus data source. Next, write `http_` in the
Metrics Browser input field and you should see the available metric names in the auto-complete drop-down.

![](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/dropdown-metrics.png)

## Add the Beyla RED Metrics Dashboard

You could start composing your PromQL queries for better visualization of
your auto-instrumented RED metrics; to save you time, we provide a sample
[public dashboard with some basic information](/grafana/dashboards/19077-beyla-red-metrics/).

To import the sample dashboard into your Grafana instance, choose "Dashboards" in the Grafana left panel.
Next, in the Dashboards page, click on the "New" drop-down menu and select "Import":

![](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/import-dashboard.png)

In the "Import via grafana.com" textbox, copy the Grafana ID from the
[Beyla RED Metrics](/grafana/dashboards/19077-beyla-red-metrics/)
dashboard: `19077`.

Rename the dashboard to match your service, select the folder and, most importantly, select the
data source in the `prometheus-data-source` drop-down at the bottom.

And _voilà!_ you can see some of your test RED metrics:

![](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/beyla-dashboard-screenshot.png)

The dashboard contains the following components:

- A list with the slowest HTTP routes for all instrumented services. Since you only
  have a single service, only one entry appears. If you configure Beyla to
  [report the HTTP routes]({{< relref "../configure/options.md#routes-decorator" >}}),
  many entries could appear there, one for each HTTP path seen by the server.
- A list with the slowest GRPC methods. Since the test service in this tutorial only
  serves HTTP, this table is empty.
- For each instrumented service, a list of RED metrics for the inbound (server) traffic. This includes:
  - Duration: average and top percentiles for both HTTP and gRPC traffic.
  - Request rate: number of requests per second, faceted by its HTTP or gRPC return code.
  - Error rate as a percentage of 5xx HTTP responses or non-zero gRPC responses over the total
    of the requests. They are faceted by return code.
- For each instrumented service, a list of RED metrics for the outbound (client) traffic. In
  the above screenshot they are empty because the test service does not perform HTTP or gRPC
  calls to other services.
  - The Duration, Request Rate and Errors charts are analogues to the inbound traffic charts,
    with the only difference that 4xx return codes are also considered errors on the
    client side.

At the top of the chart, you can use the "Service" dropdown to filter the services you
want to visualize.

## Conclusions and future work

eBPF proved to be a low-overhead, safe, and reliable way to observe some basic metrics for
HTTP/gRPC services. Beyla is not a replacement for language
specific agents, however it significantly decreases the landing time of your application insights in Grafana.
Beyla does not require any code changes, recompilation nor repackaging, simply run
it together with your service, and your application metrics will start to flow.

eBPF also allows you to get deeper insights which manual instrumentation doesn't. For example,
Beyla is able to show you how much time a request is enqueued, after
the connection is established, and before its code is actually executed (requires [exporting
OpenTelemetry traces]({{< relref "../configure/options.md#otel-traces-exporter" >}}),
but this functionality is not explained in this tutorial).

Beyla has its limitations too. It only provides generic metrics and
single spans trace information (no distributed traces, yet). Language agents and manual
instrumentation is still recommended, so that you can specify the granularity of each
part of the code to be instrumented, putting the focus on your critical operations.

Another limitation to consider is that Beyla requires
elevated privileges; not actually a `root` user, but at least it has to run with the
`CAP_SYS_ADMIN` capability. If you run the tool as a container (Docker, Kubernetes...), it
has to be privileged, or configured with the `CAP_SYS_ADMIN` capability.

In the future, we plan to add metrics about other well-established protocols, like
database or message queuing connections.

Distributed tracing is also on our road-map. With distributed tracing we will be able to correlate
requests from multiple services (web, database, messaging...). One complexity of
distributed tracing is the injection of client-side headers and matching them to the context of
the server-side requests. We are making progressive advances towards this goal with each
new pull request.

Another shorter term goal is to reduce the surface of the code that requires administrative
privileges, executing a small eBPF loader with `root` or `CAP_SYS_ADMIN` privileges,
and running the rest of data processing/exposition with normal user privileges.
