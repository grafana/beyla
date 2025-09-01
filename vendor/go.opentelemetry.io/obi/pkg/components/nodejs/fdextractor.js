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

const { AsyncLocalStorage } = require('async_hooks');

const debug_enabled = false;

console.log('OpenTelemetry eBPF Instrumentation has injected instrumentation via the NodeJS debugger');
console.log('The debugger will be deactivated again and closed');

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

  const pad4 = n => String(n).padStart(4, '0');

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
