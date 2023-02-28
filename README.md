# http-autoinstrument
eBPF-based autoinstrumentation of HTTP and HTTPS services

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

## To contribute or to not contribute

Advantages of creating our own parallel project:
- No need to deal with legacy
- Faster release pace
- Adapt workflow to our necessities (e.g. no odigos launcher)

Advantages of contributing to otel repo:
- More allocated resources
- Wider user base
- No duplicities
- No need to solve twice the same problems
- Maybe eventually our users end up forcing to adopt otel instrumentation

## How to setup a quick demo

The simplest way is to use Kubernetes and the files in the `deployments/` folder.

1. Deploy demo: you can use the blog example in the [deployments/00-demo-app.yml](./deployments/00-demo-app.yml) file.
   As a requirement, it must be compiled with Go 1.19+ and make use of the standard library HTTP handlers.
   ```
   $ kubectl apply -f ./deployments/00-demo-app.yml
   $ kubectl port-forward service/goblog 8443:8443
   ```

2. Provide your Grafana credentials. Use the following [K8s Secret template](deployments/01-example-k8s-agentconfig.yml.template)
   to introduce the endpoints, usernames and API keys for Mimir and Tempo:
   ```
   $ cp deployments/01-example-k8s-agentconfig.yml.template deployments/01-example-k8s-agentconfig.yml
   $ # EDIT the fields
   $ vim deployments/01-example-k8s-agentconfig.yml.template
   $ kubectl apply -f deployments/01-example-k8s-agentconfig.yml 
   ```
2. Deploy the auto-instrumenter+agent:
   ```
   kubectl apply -f deployments/02-auto-instrument.yml
   ```

You should be able to query traces and metrics in your Grafana board.

![img.png](img.png)


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

