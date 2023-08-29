---
title: Beyla profiling
menuTitle: Profiling
description: Learn how to profile Grafana's eBPF auto-instrumentation tool for performance analysis.
weight: 5
---

# Beyla profiling

1. Run the auto-instrumentation tool with the `PROFILE_PORT` variable set, e.g. 6060.

2. Download the required profiles:

   ```
   curl -o <profile> http://localhost:6060/debug/pprof/<profile>
   ```

   Where `<profile>` can be:

* `allocs`: A sampling of all past memory allocations
* `block`: Stack traces that led to blocking on synchronization primitives
* `cmdline`: The command line invocation of the current program
* `goroutine`: Stack traces of all current goroutines
* `heap`: A sampling of memory allocations of live objects.
    * You can specify the `gc` GET parameter to run GC before taking the heap sample.
* `mutex`: Stack traces of holders of contended mutexes
* `profile`: CPU profile.
    * You can specify the `duration` in the seconds GET parameter.
* `threadcreate`: Stack traces that led to the creation of new OS threads
* `trace`: A trace of execution of the current program.
    * You can specify the `duration` in the seconds GET parameter.

Example:

```
curl "http://localhost:6060/debug/pprof/trace?seconds=20" -o trace20s
curl "http://localhost:6060/debug/pprof/profile?duration=20" -o profile20s
curl "http://localhost:6060/debug/pprof/heap?gc" -o heap
curl "http://localhost:6060/debug/pprof/allocs" -o allocs
curl "http://localhost:6060/debug/pprof/goroutine" -o goroutine
```

3. Use `go tool pprof` to dig into the profiles (`go tool trace` for `trace` profiles)
