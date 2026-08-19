// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// OBI Node.js manual-span bridge.
//
// Captures spans created through @opentelemetry/api when the application has
// no OpenTelemetry SDK registered — the Node.js analog of the Go support in
// bpf/gotracer/go_sdk.c, which hooks the no-op global-API tracer and bails
// out when a real SDK delegate is installed.
//
// It installs a minimal, dependency-free TracerProvider as the delegate of
// each reachable @opentelemetry/api copy's ProxyTracerProvider (the copies
// present in require.cache at injection, plus any loaded later through a
// Module._load hook). It deliberately does NOT write to the API's global
// registry (globalThis[Symbol.for('opentelemetry.js.api.1')]) — occupying that
// shared slot would make a later app setGlobalTracerProvider fail the api's
// duplicate/version guard and block the app's own SDK. The trade-off: an api
// copy the module loader never sees (a bundled/inlined copy, or a native-ESM
// build) is neither captured nor blocked. Finished spans are serialized to
// JSON and signalled to the eBPF layer through the same channel fdextractor.js
// uses: a sentinel uv_fs_access() path read by the obi_uv_fs_access uprobe
// (bpf/generictracer/nodejs.c). The BPF side attaches the current request's
// trace context (traces_ctx_v1), so manual spans parent under OBI's automatic
// server spans.
//
// If the application registers its own SDK, this bridge stays inert: spans
// are then exported by the app's SDK and OBI's SDK-overlap detection applies.

(() => {
  'use strict';

  const API_KEY = Symbol.for('opentelemetry.js.api.1');
  // Same Symbol.for key the api uses internally (createContextKey).
  const SPAN_KEY = Symbol.for('OpenTelemetry Context Key SPAN');
  const SENTINEL_PREFIX = '/dev/null/obi-span/';
  // Field size budgets. Attribute key/value budgets must match the fixed
  // BPF/Go otel_attribute_t buffers on the reader side (key[32], value[128]),
  // minus one byte for the NUL terminator the decoder relies on — otherwise
  // the userspace decoder silently re-truncates and we waste payload space.
  const MAX_PAYLOAD = 1900; // whole serialized span; keeps the sentinel path under the BPF buffer
  const MAX_ATTRS = 16;
  const MAX_NAME_LEN = 128;
  const MAX_ATTR_KEY_LEN = 31; // otel_attribute_t key[32] - 1 (NUL)
  const MAX_ATTR_VALUE_LEN = 127; // otel_attribute_t value[128] - 1 (NUL)
  const MAX_STATUS_MSG_LEN = 128;

  const g = globalThis;
  if (g.__obiSpanBridgeLoaded) return;
  g.__obiSpanBridgeLoaded = true;

  const fs = require('fs');
  const crypto = require('crypto');
  const { AsyncLocalStorage } = require('async_hooks');

  // Diagnostics are OFF by default: this code runs inside the customer's
  // process, so it must never write to their stdout/stderr in normal
  // operation. Set OTEL_EBPF_NODEJS_DEBUG=1 to surface why the
  // bridge failed to activate when troubleshooting an injection.
  const DEBUG = !!process.env.OTEL_EBPF_NODEJS_DEBUG;
  const debug = (msg, err) => {
    if (!DEBUG) return;
    try {
      const reason = err ? ': ' + (err.stack || err.message || String(err)) : '';
      console.error('[obi-span-bridge] ' + msg + reason);
    } catch (_) {
      // never let diagnostics throw into the app
    }
  };

  // Truncate a string to a UTF-8 BYTE budget, never splitting a multi-byte
  // sequence. The BPF/Go side copies keys/values into fixed byte arrays, so a
  // UTF-16 code-unit budget (String#length) is wrong twice over: a multi-byte
  // character can blow the byte budget while passing the unit check, and a cut
  // inside a sequence would export invalid UTF-8.
  const truncateUtf8 = (s, maxBytes) => {
    if (Buffer.byteLength(s, 'utf8') <= maxBytes) return s;
    const buf = Buffer.from(s, 'utf8');
    let end = maxBytes;
    // Find the start of the sequence containing the cut point; drop the
    // sequence if the cut left it incomplete.
    let i = end - 1;
    while (i >= 0 && (buf[i] & 0xc0) === 0x80) i--;
    if (i >= 0 && buf[i] >= 0x80) {
      const lead = buf[i];
      const seqLen = lead >= 0xf0 ? 4 : lead >= 0xe0 ? 3 : 2;
      if (end - i < seqLen) end = i;
    }
    return buf.subarray(0, end).toString('utf8');
  };

  // App-provided values (span names, attribute values, status messages) may be
  // objects whose toString()/Symbol.toPrimitive throws. This code runs inside
  // the customer's process on the hot path (span.end() is often in a finally
  // block), so a raw String(value) that throws would surface as an app-level
  // exception where an unregistered SDK would have been a silent no-op. Coerce
  // defensively and never let stringification escape.
  const safeStr = (v) => {
    try {
      return String(v);
    } catch (_) {
      return '';
    }
  };

  // IMPORTANT: do not create or modify the registry until every guard has
  // passed — a registry object we create carries a version string, and any
  // app api copy with a different exact version would then fail its own
  // setGlobalTracerProvider (registerGlobal requires an exact version match
  // between registrants).
  const existing = g[API_KEY];
  // An SDK (or another agent) already registered a provider or context
  // manager — stay inert rather than fight it.
  if (existing && (existing.trace || existing.context)) {
    debug('staying inert: a tracer provider/context manager is already registered');
    return;
  }
  // We deliberately DO NOT write to the global registry (globalThis[API_KEY]).
  // Occupying its `trace`/`context` slots — or even creating the object with
  // our `version` — would make a later app `setGlobalTracerProvider` fail the
  // api's duplicate/exact-version guard, so the app's own SDK could never take
  // over. Instead we capture purely by pointing each reachable api copy's
  // ProxyTracerProvider at our provider (see wireApiCopy). The cost is that api
  // copies we cannot reach through the module loader — a bundled/inlined api
  // (webpack/esbuild) or a genuine native-ESM copy — are neither captured nor
  // blocked. See devdocs/nodejs-manual-spans.md ("Unreachable api copies").

  // Step-aside state: once the application registers its own provider, we stop
  // emitting and forward pre-acquired tracers so its SDK owns the API surface.
  // Nothing to un-register — we never occupied the global registry.
  let yielded = false;
  const yieldToApp = (why) => {
    if (yielded) return;
    yielded = true;
    debug('yielded to application-registered SDK: ' + why);
  };

  // --- transport -----------------------------------------------------------

  // The span payload is smuggled to the eBPF layer as the argument of a
  // deliberately-failing uv_fs_access() call: the obi_uv_fs_access uprobe
  // reads the path string on syscall entry, then the syscall itself fails
  // because the path does not exist. So the throw here is the EXPECTED,
  // every-span outcome (ENOENT/ENOTDIR) — not an error, and not something we
  // can log per span without flooding the app. It also does not tell us
  // whether OBI actually consumed the event: an attached uprobe and a
  // not-attached OBI produce the identical failure. Only a genuinely
  // unexpected error (e.g. a malformed payload rejected before the syscall)
  // is worth surfacing, and only under the debug flag.
  const emit = (payload) => {
    // Stop emitting once the app's SDK owns telemetry: either we yielded via a
    // wrapped setter, or an api copy we could not wrap registered the app
    // provider straight into the global registry (detectRegistryHandoff).
    if (yielded || detectRegistryHandoff()) return;
    try {
      fs.accessSync(SENTINEL_PREFIX + payload);
    } catch (err) {
      if (DEBUG && err && err.code !== 'ENOENT' && err.code !== 'ENOTDIR') {
        debug('unexpected error emitting span', err);
      }
    }
  };

  // --- minimal context implementation --------------------------------------

  class Context {
    constructor(entries) {
      this._entries = entries ?? new Map();
    }
    getValue(key) {
      return this._entries.get(key);
    }
    setValue(key, value) {
      const m = new Map(this._entries);
      m.set(key, value);
      return new Context(m);
    }
    deleteValue(key) {
      const m = new Map(this._entries);
      m.delete(key);
      return new Context(m);
    }
  }

  const ROOT_CONTEXT = new Context();
  const als = new AsyncLocalStorage();

  const contextManager = {
    active() {
      return als.getStore() ?? ROOT_CONTEXT;
    },
    with(context, fn, thisArg, ...args) {
      return als.run(context ?? ROOT_CONTEXT, () => fn.call(thisArg, ...args));
    },
    bind(context, target) {
      if (typeof target === 'function') {
        const self = this;
        return function (...args) {
          return self.with(context, target, this, ...args);
        };
      }
      return target;
    },
    enable() {
      return this;
    },
    disable() {
      return this;
    },
  };

  // --- minimal recording span ----------------------------------------------

  const nowNs = () => {
    // Wall-clock start anchor + monotonic offset for sub-ms durations.
    return BigInt(Date.now()) * 1000000n;
  };
  const hrNs = () => process.hrtime.bigint();

  class Span {
    constructor(name, kind, parentSpanContext, extParent) {
      this.name = safeStr(name);
      this.kind = kind ?? 0;
      this._parent = parentSpanContext;
      // True when the parent context came from a span the bridge does not own
      // (an app/remote SpanContext). User space must not keep such a parent id
      // while re-anchoring the span onto the OBI request trace — that would
      // export a cross-trace parent reference.
      this._extParent = !!(parentSpanContext && extParent);
      this._spanContext = {
        traceId: parentSpanContext
          ? parentSpanContext.traceId
          : crypto.randomBytes(16).toString('hex'),
        spanId: crypto.randomBytes(8).toString('hex'),
        traceFlags: 1,
        traceState: undefined,
      };
      this.attributes = {};
      this.status = { code: 0 };
      this._events = [];
      this._startWallNs = nowNs();
      this._startHrNs = hrNs();
      this._ended = false;
    }
    spanContext() {
      return this._spanContext;
    }
    setAttribute(key, value) {
      if (!this._ended && typeof key === 'string') this.attributes[key] = value;
      return this;
    }
    setAttributes(attrs) {
      for (const k of Object.keys(attrs ?? {})) this.setAttribute(k, attrs[k]);
      return this;
    }
    addEvent(name) {
      if (!this._ended && this._events.length < 8) this._events.push(safeStr(name));
      return this;
    }
    addLink() {
      return this;
    }
    addLinks() {
      return this;
    }
    setStatus(status) {
      if (!this._ended && status && typeof status.code === 'number') {
        this.status = { code: status.code, message: status.message };
      }
      return this;
    }
    updateName(name) {
      if (!this._ended) this.name = safeStr(name);
      return this;
    }
    recordException(err) {
      const msg = err && (err.message ?? safeStr(err));
      if (msg !== undefined) this.setAttribute('exception.message', safeStr(msg));
      return this;
    }
    isRecording() {
      return !this._ended;
    }
    end() {
      if (this._ended) return;
      this._ended = true;
      const durNs = hrNs() - this._startHrNs;
      // span.end() is idiomatically called from a finally block. It must never
      // throw into the app: with no SDK registered the alternative is a silent
      // NoopSpan, so any escape here is a regression. safeStr guards the field
      // coercions; this catch is the last line of defense (e.g. an exotic
      // JSON.stringify failure).
      try {
        this._emit(durNs);
      } catch (err) {
        debug('failed to emit span (dropped)', err);
      }
    }
    // Serialize at most MAX_ATTRS attributes into a plain object, truncating
    // keys/values and coercing unsupported value types to strings, to match
    // what the BPF-side fixed-size attribute layout can carry.
    _serializeAttributes() {
      const out = {};
      let count = 0;
      for (const [rawKey, value] of Object.entries(this.attributes)) {
        if (count >= MAX_ATTRS) break;
        count++;
        const key = truncateUtf8(rawKey, MAX_ATTR_KEY_LEN);
        if (typeof value === 'string') {
          out[key] = truncateUtf8(value, MAX_ATTR_VALUE_LEN);
        } else if (typeof value === 'number' || typeof value === 'boolean') {
          out[key] = value;
        } else {
          out[key] = truncateUtf8(safeStr(value), MAX_ATTR_VALUE_LEN);
        }
      }
      return out;
    }
    _emit(durNs) {
      const rec = {
        v: 1,
        name: truncateUtf8(this.name, MAX_NAME_LEN),
        tid: this._spanContext.traceId,
        sid: this._spanContext.spanId,
        psid: this._parent ? this._parent.spanId : undefined,
        extParent: this._extParent ? true : undefined,
        kind: this.kind,
        startNs: this._startWallNs.toString(),
        durNs: durNs.toString(),
        status: this.status.code,
        statusMsg: this.status.message ? truncateUtf8(safeStr(this.status.message), MAX_STATUS_MSG_LEN) : undefined,
        attrs: this._serializeAttributes(),
      };
      let payload = JSON.stringify(rec);
      // Measure UTF-8 bytes, not String#length (UTF-16 code units): the BPF
      // side reads the sentinel path as bytes into a fixed buffer, so a
      // multi-byte payload that looks short by .length could still overflow.
      if (Buffer.byteLength(payload, 'utf8') > MAX_PAYLOAD) {
        rec.attrs = {};
        payload = JSON.stringify(rec);
      }
      if (Buffer.byteLength(payload, 'utf8') > MAX_PAYLOAD) {
        debug('dropping span: core payload exceeds transport limit');
        return;
      }
      emit(payload);
    }
  }

  // --- tracer / provider ----------------------------------------------------

  // The application can register its own provider through an @opentelemetry/api
  // copy we could not wrap — a bundled/inlined copy, or any copy that never
  // reached our setter wrapping — by writing the shared global registry
  // directly. That path never calls our wrapped setGlobalTracerProvider, so
  // `yielded` would stay false and the bridge would keep emitting alongside the
  // app's SDK, splitting telemetry across two providers in one process. Treat a
  // non-bridge provider appearing in the registry as an explicit handoff
  // signal: flip us into the yielded state (idempotent) and return the app
  // provider so cached tracers re-route to it.
  const detectRegistryHandoff = () => {
    const reg = g[API_KEY];
    const prov = reg && reg.trace;
    if (prov && prov !== tracerProvider && typeof prov.getTracer === 'function') {
      yieldToApp('application provider present in global registry');
      return prov;
    }
    return null;
  };

  // After we have yielded, the application's own provider owns the global.
  // Tracers the app acquired-and-used before injection cached OUR tracer
  // (OTel ProxyTracer caches the first real delegate), so route them through
  // to the app's current tracer instead of producing dead bridge spans. The
  // registry-appearance check also hands off for apps that registered through
  // a copy we could not wrap.
  const activeAppTracer = (scope, version) => {
    if (!yielded && !detectRegistryHandoff()) return null;
    const reg = g[API_KEY];
    const prov = reg && reg.trace;
    if (prov && typeof prov.getTracer === 'function') return prov.getTracer(scope, version);
    return null;
  };

  class Tracer {
    constructor(scopeName) {
      this._scope = scopeName;
    }
    startSpan(name, options, context) {
      const at = activeAppTracer(this._scope);
      if (at) return at.startSpan(name, options, context);
      const ctx = context ?? contextManager.active();
      const opts = options ?? {};
      let parent;
      let extParent = false;
      if (opts.root !== true) {
        const parentSpan = ctx.getValue(SPAN_KEY);
        if (parentSpan && typeof parentSpan.spanContext === 'function') {
          const sc = parentSpan.spanContext();
          if (sc && typeof sc.traceId === 'string' && /^[0-9a-f]{32}$/.test(sc.traceId)) {
            parent = sc;
            extParent = !(parentSpan instanceof Span);
          }
        }
      }
      const span = new Span(name, opts.kind, parent, extParent);
      span._scope = this._scope;
      if (opts.attributes) span.setAttributes(opts.attributes);
      return span;
    }
    startActiveSpan(name, arg2, arg3, arg4) {
      const at = activeAppTracer(this._scope);
      if (at) return at.startActiveSpan(name, arg2, arg3, arg4);
      let options, context, fn;
      if (typeof arg2 === 'function') {
        fn = arg2;
      } else if (typeof arg3 === 'function') {
        options = arg2;
        fn = arg3;
      } else {
        options = arg2;
        context = arg3;
        fn = arg4;
      }
      if (typeof fn !== 'function') return undefined;
      const parentCtx = context ?? contextManager.active();
      const span = this.startSpan(name, options, parentCtx);
      const ctx = parentCtx.setValue(SPAN_KEY, span);
      return contextManager.with(ctx, fn, undefined, span);
    }
  }

  const tracerProvider = {
    getTracer(name, _version, _options) {
      return new Tracer(name || 'unknown');
    },
  };

  // --- register into the shared api global registry -------------------------

  // Wrap a global setter on an api namespace so that, if the application ever
  // registers its own provider/manager, we yield first (removing our registry
  // entry) and then let the real registration proceed — so the app's SDK wins
  // instead of hitting the API's "duplicate registration" refusal.
  const wrapSetter = (apiObj, method, why) => {
    if (!apiObj || typeof apiObj[method] !== 'function' || apiObj[method].__obiWrapped) {
      return;
    }
    const orig = apiObj[method].bind(apiObj);
    const wrapped = function (...args) {
      yieldToApp(why);
      return orig(...args);
    };
    wrapped.__obiWrapped = true;
    apiObj[method] = wrapped;
  };

  // Wire a single @opentelemetry/api copy to the bridge. Because we never
  // occupy the global registry, getTracerProvider() returns this copy's own
  // ProxyTracerProvider, so we:
  //   - point that ProxyTracerProvider at our provider, so tracers acquired
  //     through this copy (a ProxyTracer caches the first delegate and never
  //     re-consults the registry) resolve to us; and
  //   - wrap its global setters so the app's own SDK registration makes us
  //     yield and stop emitting, rather than the bridge lingering.
  const wiredApis = new WeakSet();
  const wireApiCopy = (exp) => {
    if (yielded || !exp || wiredApis.has(exp)) return;
    const traceApi = exp.trace;
    const contextApi = exp.context;
    if (!traceApi || typeof traceApi.getTracerProvider !== 'function') return;
    wiredApis.add(exp);
    const proxy = traceApi.getTracerProvider();
    if (proxy && proxy !== tracerProvider && typeof proxy.setDelegate === 'function') {
      proxy.setDelegate(tracerProvider);
    }
    // Yield when the app registers its own tracer provider / context manager.
    wrapSetter(traceApi, 'setGlobalTracerProvider', 'setGlobalTracerProvider');
    wrapSetter(contextApi, 'setGlobalContextManager', 'setGlobalContextManager');
  };

  // Copies already loaded before us (present in require.cache).
  for (const key of Object.keys(require.cache ?? {})) {
    if (!/[\\/]@opentelemetry[\\/]api[\\/]/.test(key)) continue;
    try {
      wireApiCopy(require.cache[key] && require.cache[key].exports);
    } catch (err) {
      // never let bridge wiring break the app; surface only under debug
      debug('failed to wire pre-loaded @opentelemetry/api copy ' + key, err);
    }
  }

  // We do NOT set registry.trace / registry.context (see the note above): the
  // bridge captures only through the per-copy ProxyTracerProvider delegate wired
  // in wireApiCopy, never by occupying the global registry.

  // Cover @opentelemetry/api copies loaded AFTER injection: an app that requires
  // the api (and its SDK) only after we injected needs that copy wired too, so
  // its ProxyTracerProvider routes to us and its setGlobalTracerProvider is
  // wrapped for the step-aside. Hook the CommonJS module loader and wire each
  // api copy as it loads. We call the original loader first and guard
  // everything, so this composes with other loader patches (e.g.
  // import-in-the-middle) and can never break a require. Note: `import
  // '@opentelemetry/api'` also flows through here, because the package ships a
  // CommonJS entry (no `import`/`node` export condition), so native-ESM apps are
  // covered too. Only an api copy that never reaches the CommonJS loader — a
  // bundled/inlined copy, or a hypothetical native-ESM build of the api — is
  // left unwired (and, per the design, unblocked).
  try {
    const Module = require('module');
    const origLoad = Module._load;
    if (typeof origLoad === 'function' && !origLoad.__obiWrapped) {
      const patchedLoad = function (request) {
        const exported = origLoad.apply(this, arguments);
        try {
          if (!yielded && /(?:^|[\\/])@opentelemetry[\\/]api(?:[\\/]|$)/.test(String(request))) {
            wireApiCopy(exported);
          }
        } catch (err) {
          debug('module-load api wiring failed', err);
        }
        return exported;
      };
      patchedLoad.__obiWrapped = true;
      Module._load = patchedLoad;
    }
  } catch (err) {
    debug('failed to install module-load hook', err);
  }

  g.__obiSpanBridge = { version: 1 };
  debug('span bridge activated (pid ' + process.pid + ')');
})();
