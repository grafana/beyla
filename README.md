<img src="docs/sources/assets/logo.png" height=226 alt="Grafana Beyla logo">

# Grafana Beyla

Open source zero-code automatic instrumentation with eBPF and OpenTelemetry.

[![Build Status](https://drone.grafana.net/api/badges/grafana/beyla/status.svg?ref=refs/heads/main)](https://drone.grafana.net/grafana/beyla)

:green_circle: **We are hiring!** :green_circle: If you want to become a Beyla engineer, find our job post [here](https://boards.greenhouse.io/grafanalabs/jobs/5019971004).

## Introduction

Beyla is a vendor agnostic, eBPF-based, OpenTelemetry/Prometheus application auto-instrumentation tool, which lets you easily get started with Application Observability. 
eBPF is used to automatically inspect application executables and the OS networking layer, allowing us to capture essential application observability events
for HTTP/S and gRPC services. From these captured eBPF events, we produce OpenTelemetry web transaction trace spans and Rate-Errors-Duration (RED) metrics. 
As with most eBPF tools, all data capture and instrumentation occurs without any modifications to your application code or configuration.

## Community

To engage with the Beyla community and to chat with us on our community Slack channel, 
please invite yourself to the Grafana Slack, visit https://slack.grafana.com/ and join the #beyla channel.

We also run a monthly Beyla community call, on the second Wednesday of the month at **4pm UTC**. You can
find all of the details about our community call on the [Grafana Community Calendar](https://calendar.google.com/calendar/u/0/embed?src=grafana.com_n57lluqpn4h4edroeje6199o00@group.calendar.google.com).

## Getting Started

To try out Beyla, you need to run a network service for Beyla to instrument.
Beyla supports a wide range of programming languages (Go, Java, .NET, NodeJS, Python, Ruby, Rust, etc.),
so if you already have an example service you can use it.
If you don't have an example, you can download and run `example-http-service.go` from the `examples/` directory:

```
curl -OL https://raw.githubusercontent.com/grafana/beyla/main/examples/example-http-service/example-http-service.go
go run ./example-http-service.go
```

Next, generate some traffic. The following command will trigger a GET request to http://localhost:8080 every two seconds.

```
watch curl -s http://localhost:8080
```

Now that we have an example running, we are ready to download and run Beyla.

First, download and unpack the latest release from the [GitHub releases page](https://github.com/grafana/beyla/releases).
The release should contain the `./beyla` executable.

Beyla supports multiple ways to find the service to be instrumented (by network port, executable name, process ID),
and multiple exposition formats (Prometheus, OpenTelemetry metrics, Distributed Traces for Go, Single Span traces for 
other languages).

For getting started, we'll tell Beyla to instrument the service running on port 8080 (our example service) and expose metrics in Prometheus format on port 9400.

```
export BEYLA_PROMETHEUS_PORT=9400
export BEYLA_OPEN_PORT=8080
sudo -E ./beyla
```

Now, you should see metrics on [http://localhost:9400/metrics](http://localhost:9400/metrics).

See [Documentation](https://grafana.com/docs/beyla/) and the [tutorials](https://grafana.com/docs/beyla/latest/tutorial/) for more info.

## Requirements

- Linux with Kernel 5.8 or higher with [BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html)
  enabled. BTF became enabled by default on most Linux distributions with kernel 5.14 or higher. 
  You can check if your kernel has BTF enabled by verifying if `/sys/kernel/btf/vmlinux` exists on your system.
  If you need to recompile your kernel to enable BTF, the configuration option `CONFIG_DEBUG_INFO_BTF=y` must be
  set. 
- eBPF enabled in the host
- For instrumenting Go programs, they must have been compiled with at least Go 1.17. We currently
  support Go applications built with a major **Go version no earlier than 3 versions** behind the current
  stable major release.  
- Administrative access to execute the instrumenter
    - Or execute it from a user enabling the `SYS_ADMIN` capability. This might not work in some
      container environments.

| Library                                       | Working  |
|-----------------------------------------------|----------|
| Kernel-level HTTP calls                       | ✅       |
| OpenSSL library                               | ✅       |
| Standard Go `net/http`                        | ✅       |
| [Gorilla Mux](https://github.com/gorilla/mux) | ✅       |
| [Gin](https://gin-gonic.com/)                 | ✅       |
| [gRPC-Go](https://github.com/grpc/grpc-go)    | ✅       |

## Kubernetes

You can just trigger the Kubernetes descriptors in the `deployments/` folder.

1. Provide your Grafana credentials. Use the following [K8s Secret template](deployments/01-grafana-credentials.template.yml)
   to introduce the endpoints, usernames and API keys for Mimir and Tempo:
   ```
   $ cp deployments/01-grafana-credentials.template.yml 01-grafana-credentials.yml
   $ # EDIT the fields
   $ vim 01-grafana-credentials.yml
   $ kubectl apply -f 01-grafana-credentials.yml 
   ```
2. Deploy the Grafana Agent:
   ```
   kubectl apply -f deployments/02-grafana-agent.yml
   ```

3. Deploy a demo app with the auto-instrumenter as a sidecar. You can use the blog example in the
   [deployments/03-instrumented-app.yml](./deployments/03-instrumented-app.yml) file.
   
   ```
   $ kubectl apply -f ./deployments/03-instrumented-app.yml
   $ kubectl port-forward service/goblog 8443:8443
   ```

You should be able to query traces and metrics in your Grafana board.

## Development recipes

### How to regenerate the eBPF Kernel binaries

The eBPF program is embedded into the `pkg/internal/ebpf/bpf_*` generated files.
This step is generally not needed unless you change the C code in the `bpf` folder.

If you have Docker installed, you just need to run:

```
make docker-generate
```

If you can't install docker, you should locally install the following required packages:

```
dnf install -y kernel-devel make llvm clang glibc-devel.i686
make generate
```

Tested in Fedora 35, 38 and Red Hat Enterprise Linux 8.

## Credits

Part of the code is taken from: https://github.com/open-telemetry/opentelemetry-go-instrumentation
