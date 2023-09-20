<img src="docs/sources/assets/logo.png" height=226 alt="Grafana Beyla logo">

# Grafana Beyla

eBPF-based auto-instrumentation of HTTP/HTTPS/GRPC Go services, as well as HTTP/HTTPS services
written in other languages (intercepting Kernel-level socket operations as well as
OpenSSL invocations).

[![Build Status](https://drone.grafana.net/api/badges/grafana/beyla/status.svg?ref=refs/heads/main)](https://drone.grafana.net/grafana/beyla)


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
and multiple exposition formats (Prometheus, OpenTelemetry metrics, Single Span traces).

For getting started, we'll tell Beyla to instrument the service running on port 8080 (our example service) and expose metrics in Prometheus format on port 9400.

```
export BEYLA_PROMETHEUS_PORT=9400
export OPEN_PORT=8080
sudo -E ./beyla
```

Now, you should see metrics on [http://localhost:9400/metrics](http://localhost:9400/metrics).

See [Documentation](https://grafana.com/docs/grafana-cloud/monitor-applications/beyla/) and the [quickstart tutorial](docs/sources/tutorial/index.md) for more info.

## Requirements

- Linux with Kernel 4.18 or higher
- eBPF enabled in the host
- For instrumenting Go programs, they must have been compiled with Go 1.17 or higher
- Administrative access to execute the instrumenter
    - Or execute it from a user enabling the `SYS_ADMIN` capability.
- If you want to instrument HTTP calls at kernel-level (for other languages than Go),
  your Kernel needs to enable BTF ([compiled with `CONFIG_DEBUG_INFO_BTF`](https://www.baeldung.com/linux/kernel-config))

| Library                                       | Working |
|-----------------------------------------------|---------|
| Kernel-level HTTP calls                       | ✅       |
| OpenSSL library                               | ✅       |
| Standard `net/http`                           | ✅       |
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
