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
