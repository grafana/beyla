# http-autoinstrument
eBPF-based autoinstrumentation of HTTP and HTTPS services

Part of the code is taken from: https://github.com/open-telemetry/opentelemetry-go-instrumentation

* bpf/**

Differences:

* No need to maintain old Go versions (e.g. stack-based parameters)
* We assume Dwarf info is enabled
  * Instead of using process maps for function delimitation, we just use Dwarf
  * 
