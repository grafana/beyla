# eBPF autoinstrumenter

[![Build Status](https://drone.grafana.net/api/badges/grafana/ebpf-autoinstrument/status.svg?ref=refs/heads/main)](https://drone.grafana.net/grafana/ebpf-autoinstrument)

eBPF-based autoinstrumentation of HTTP and HTTPS services

| Library                                       | Working |
|-----------------------------------------------|---------|
| Standard `net/http`                           | ✅       |
| [Gorilla Mux](https://github.com/gorilla/mux) | ✅       |
| [Gin](https://gin-gonic.com/)                 | ❌       |

## Credits

Part of the code is taken from: https://github.com/open-telemetry/opentelemetry-go-instrumentation

* bpf/**

Differences:

* No need to maintain old Go versions (e.g. stack-based parameters)
* We assume Dwarf info is enabled
  * Instead of using process maps for function delimitation, we just use Dwarf
* standard HTTP instrumentation works
  * Original didn't work in Go 1.17+ because it uses registers https://github.com/keyval-dev/opentelemetry-go-instrumentation/issues/45
  * We use a pointer to the goroutine as map key
* They can't fetch uretprobe info
  * Registers change during the function
  * We store the initial set of registers at the start of the function and retrieve them at the end of the function
* Using ringbuffer instead of perf_buffer
  * despite the name, ringbuffer is faster
* We return status code

## How to setup a quick demo

The simplest way is to use Kubernetes and the files in the `deployments/` folder.

1. Provide your Grafana credentials. Use the following [K8s Secret template](deployments/01-example-k8s-agentconfig.yml.template)
   to introduce the endpoints, usernames and API keys for Mimir and Tempo:
   ```
   $ cp deployments/01-example-k8s-agentconfig.yml.template deployments/01-example-k8s-agentconfig.yml
   $ # EDIT the fields
   $ vim deployments/01-example-k8s-agentconfig.yml.template
   $ kubectl apply -f deployments/01-example-k8s-agentconfig.yml 
   ```
2. Deploy the Grafana Aent:
   ```
   kubectl apply -f deployments/02-grafana-agent.yml
   ```

3. Deploy a demo app with the auto-instrumenter as a sidecar. You can use the blog example in the
   [deployments/03-instrumented-app.yml](./deployments/03-instrumented-app.yml) file.
   
   ```
   $ kubectl apply -f ./deployments/03-instrumented-app
   $ kubectl port-forward service/goblog 8443:8443
   ```

You should be able to query traces and metrics in your Grafana board.

## Development recipes

### How to regenerate the eBPF Kernel binaries

The eBPF program is embedded into the `pkg/ebpf/bpf_*` generated files.
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

