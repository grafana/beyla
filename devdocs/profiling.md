# Beyla profiling

To profile a Beyla while it is instrumenting an application do the following:

1. Run Beyla with the `BEYLA_PROFILE_PORT` variable set, e.g. 6060.
2. Download the required profiles:

   ```sh
   curl -o <profile> http://localhost:6060/debug/pprof/<profile>
   ```

   Where `<profile>` can be:

   - `allocs`: a sample of all past memory allocations
   - `block`: stack traces that led to blocking on synchronization primitives
   - `cmdline`: the command to run the program to profile
   - `goroutine`: stack traces of all current goroutines
   - `heap`: a sample of memory allocations of live objects
     - provide an optional `gc` query parameter to run the GC before sampling the heap
   - `mutex`: stack traces of holders of contended mutexes
   - `profile`: CPU profile
     - provide an optional `duration` query parameter in seconds
   - `threadcreate`: stack traces that led to the creation of new OS threads
   - `trace`: a trace of execution of the current program
     - provide an optional `duration` query parameter in seconds

   Example:

   ```sh
   curl "http://localhost:6060/debug/pprof/trace?seconds=20" -o trace20s
   curl "http://localhost:6060/debug/pprof/profile?duration=20" -o profile20s
   curl "http://localhost:6060/debug/pprof/heap?gc" -o heap
   curl "http://localhost:6060/debug/pprof/allocs" -o allocs
   curl "http://localhost:6060/debug/pprof/goroutine" -o goroutine
   ```

3. Use `go tool pprof` to dig into the profiles (`go tool trace` for `trace` profiles)
