(()=>{
  const STORE = Symbol.for('otel-ebpf-instrumentation.fdextractor');

  const net = require('net');
  const fs = require('fs');

  if (!global[STORE]) {
    global[STORE] = {
      serverEmit: net.Server.prototype.emit,
      socketConnect: net.Socket.prototype.connect,
      socketWrite: net.Socket.prototype.write,
    };
  }

  const orig = global[STORE];
  net.Server.prototype.emit = orig.serverEmit;
  net.Socket.prototype.connect = orig.socketConnect;
  net.Socket.prototype.write = orig.socketWrite;
  if (orig.ctxHook) {
    orig.ctxHook.disable();
    orig.ctxHook = undefined;
  }

  const { AsyncLocalStorage, createHook } = require('async_hooks');
  const {
    monitorEventLoopDelay,
    performance,
    PerformanceObserver,
    constants,
  } = require('perf_hooks');
  const v8 = require('v8');

  const debug_enabled = false;

  // Substituted by the injector: trace-context propagation machinery is
  // per-async-operation cost (net prototype wraps + an async_hooks before
  // hook firing on every callback) and is skipped entirely for
  // metrics-only injections.
  const TRACES_ENABLED = false; /*OBI_TRACES_ENABLED*/

  if (debug_enabled) {
    console.log('OpenTelemetry eBPF Instrumentation has injected instrumentation via the NodeJS debugger');
    console.log('The debugger will be deactivated again and closed');
  }

  if (TRACES_ENABLED) {
    // ALS store holds only incomingFd
    const als = new AsyncLocalStorage();

    net.Server.prototype.emit = function (event, ...args) {
      if (event === 'connection') {
        const socket = args[0];
        const incomingFd = socket._handle && socket._handle.fd;

        if (debug_enabled) {
          console.log(
            `[incoming TCP] fd:${incomingFd}, remote=${socket.remoteAddress}:${socket.remotePort}`,
          );
        }

        return als.run({ incomingFd }, () =>
          orig.serverEmit.call(this, event, ...args),
        );
      }
      return orig.serverEmit.call(this, event, ...args);
    };

    const pad4 = n => String(n).padStart(4, '0');

    function correlate(incomingFd, outFd, socket) {
      if (incomingFd < 0 || outFd < 0 || incomingFd === outFd) {
        return Promise.resolve();
      }

      if (debug_enabled) {
        const addr = socket.remoteAddress || 'unknown';
        const port = socket.remotePort || 'unknown';

        console.log(
          `[outgoing TCP] inFd:${incomingFd}, outFd:${outFd}, to=${addr}:${port}`,
        );
      }

      try {
        fs.accessSync(`/dev/null/obi/${pad4(incomingFd)}${pad4(outFd)}`)
      } catch (err) {
      }
    }

    net.Socket.prototype.connect = function (...args) {
      const store = als.getStore();
      const sock = this;
      const result = orig.socketConnect.apply(this, args);

      if (store) {
        sock.once('connect', () => {
          const outFd = sock._handle && sock._handle.fd;
          correlate(store.incomingFd, outFd, sock);
        });
      }

      return result;
    };

    net.Socket.prototype.write = function (data, ...rest) {
      const doWrite = () => orig.socketWrite.apply(this, [data, ...rest]);

      // skip ipc writes
      if (
        this === process.stdout ||
        this === process.stderr
      ) {
        return doWrite();
      }

      const store = als.getStore();

      if (store) {
        const outFd = this._handle && this._handle.fd;
        correlate(store.incomingFd, outFd, this);
      }

      return doWrite();
    };

    // Signal the BPF layer before each async callback so it can restore the correct
    // trace context for this request into traces_ctx_v1.
    // fs.accessSync is safe inside async_hooks callbacks: synchronous fs operations
    // do not create AsyncWrap objects and therefore do not re-trigger this hook.
    //
    // When a callback fires OUTSIDE any request (e.g. a background timer, or a
    // callback that ran after its request finished), the kernel map would otherwise
    // still hold the last request's context — so a manual span ending in that
    // callback (bpf/generictracer/nodejs.c: obi_ctx__get) would be mis-parented
    // into that stale trace. We therefore emit an explicit clear when leaving
    // request scope. To avoid a synchronous syscall on every non-request callback
    // (there can be very many), we only clear on the request -> no-request
    // transition, tracked by `ctxActive`; a subsequent request callback re-sets it.
    let ctxActive = false;
    orig.ctxHook = createHook({
      before() {
        const store = als.getStore();
        if (store && store.incomingFd != null && store.incomingFd >= 0) {
          ctxActive = true;
          try {
            fs.accessSync(`/dev/null/obi-ctx/${pad4(store.incomingFd)}`);
          } catch (_) {}
        } else if (ctxActive) {
          ctxActive = false;
          try {
            // Explicit "no request context" signal: obi_uv_fs_access deletes the
            // traces_ctx_v1 entry so later spans are not parented into a stale trace.
            fs.accessSync('/dev/null/obi-noreqctx');
          } catch (_) {}
        }
      },
    });
    orig.ctxHook.enable();
  }

  // Runtime metrics (nodejs.eventloop.*): sample eventLoopUtilization and
  // monitorEventLoopDelay and pass them to the eBPF layer through the same
  // fs.access side channel; the payload format is documented at the decoder
  // (bpf/generictracer/nodejs.c). The interval is fixed: this script is
  // embedded verbatim, so making it configurable means templating it.
  const RT_SAMPLING_INTERVAL_MS = 1000;

  // Substituted by the injector from the same gate that sets the
  // nodejs_runtime_metrics_enabled BPF constant. When false (injection
  // triggered by traces only) the sampling machinery is never installed —
  // notably monitorEventLoopDelay's internal 10ms timer, which would
  // otherwise wake an idle event loop ~100 times per second.
  const RT_ENABLED = false; /*OBI_RT_ENABLED*/

  // Cleanup stays outside the gate: a re-injection with runtime metrics
  // disabled must tear down what a previous injection installed.
  if (orig.rtTimer) {
    clearInterval(orig.rtTimer);
    orig.rtTimer = undefined;
  }
  if (!RT_ENABLED && orig.rtHistogram) {
    orig.rtHistogram.disable();
    orig.rtHistogram = undefined;
  }
  if (!RT_ENABLED && orig.gcObserver) {
    orig.gcObserver.disconnect();
    orig.gcObserver = undefined;
  }

  // eventLoopUtilization needs Node 14.10+. Without this guard the interval
  // callback below would throw an uncaught TypeError, which by default
  // terminates the application. Older runtimes simply report no runtime
  // metrics.
  if (RT_ENABLED &&
      typeof performance.eventLoopUtilization === 'function' &&
      typeof monitorEventLoopDelay === 'function') {
    if (!orig.rtHistogram) {
      orig.rtHistogram = monitorEventLoopDelay({ resolution: 10 });
      orig.rtHistogram.enable();
    }

    const rtHex = (v) => {
      const n = Number.isFinite(v) && v > 0 ? Math.round(v) : 0;
      return n.toString(16).padStart(16, '0');
    };

    if (!orig.gcObserver) {
      // OBI wire codes (one hex char), looked up from THIS runtime's
      // constants: the constant values differ across Node versions (e.g.
      // major is 2 on older V8s, 4 on Node 26+), so they are never emitted
      // verbatim. Unknown kinds are skipped so the kind slot is always
      // exactly one character.
      const gcKindHex = {
        [constants.NODE_PERFORMANCE_GC_MINOR]: '1',
        [constants.NODE_PERFORMANCE_GC_MAJOR]: '2',
        [constants.NODE_PERFORMANCE_GC_INCREMENTAL]: '3',
        [constants.NODE_PERFORMANCE_GC_WEAKCB]: '4',
      };
      orig.gcObserver = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          // detail.kind since Node 16; before that the kind sits directly on
          // the entry (deprecated accessor, the only form on 14.10-15.x)
          const kind = gcKindHex[entry.detail ? entry.detail.kind : entry.kind];
          if (!kind) {
            continue;
          }
          try {
            // entry.duration is milliseconds; the wire carries nanoseconds
            fs.accessSync(`/dev/null/obi-v8/g${kind}${rtHex(entry.duration * 1e6)}`);
          } catch (_) {}
        }
      });
      orig.gcObserver.observe({ entryTypes: ['gc'] });
    }

    orig.rtTimer = setInterval(() => {
      const h = orig.rtHistogram;
      const elu = performance.eventLoopUtilization();
      // Histogram.count needs Node 16.14+. Before that it is undefined, so
      // empty stays false and rtHex clamps the count field to 0 — the
      // exporters then skip the delay gauges while ELU keeps working.
      const empty = h.count === 0;
      const fields = [
        elu.idle * 1e6, // eventLoopUtilization reports milliseconds
        elu.active * 1e6,
        empty ? 0 : h.min,
        empty ? 0 : h.max,
        empty ? 0 : h.mean,
        empty ? 0 : h.stddev,
        empty ? 0 : h.percentile(50),
        empty ? 0 : h.percentile(90),
        empty ? 0 : h.percentile(99),
        h.count,
      ];
      h.reset();
      try {
        fs.accessSync(`/dev/null/obi-rt/${fields.map(rtHex).join('')}`);
      } catch (_) {}
      // v8js heap metrics: one h-record per heap space, numbers at fixed
      // offsets, the engine-defined space name last (the path NUL ends it)
      for (const s of v8.getHeapSpaceStatistics()) {
        try {
          fs.accessSync(`/dev/null/obi-v8/h${rtHex(s.space_size)}${rtHex(s.space_used_size)}${rtHex(s.space_available_size)}${rtHex(s.physical_space_size)}${s.space_name}`);
        } catch (_) {}
      }
    }, RT_SAMPLING_INTERVAL_MS);
    orig.rtTimer.unref();
  }
})()
