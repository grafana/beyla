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

function crc8(data) {
  let crc = 0x00;
  const polynomial = 0x07;

  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];

    for (let bit = 0; bit < 8; bit++) {
      if (crc & 0x80) {
        crc = ((crc << 1) ^ polynomial) & 0xff;
      } else {
        crc = (crc << 1) & 0xff;
      }
    }
  }

  return crc;
}

const ipcServer = net.createServer();

ipcServer.listen(0, '127.0.0.1', () => {
  if (!debug_enabled) return;

  const addr = ipcServer.address();
  console.log(`[ipc] server listening`);
});

let ipcClient;

ipcServer.on('listening', () => {
  const { port, address } = ipcServer.address();
  ipcClient = net.connect(port, address, () => {
    ipcClient.setNoDelay(true);
    if (debug_enabled) {
      console.log(`[ipc] client connected to server`);
    }
  });
});

ipcServer.on('connection', (socket) => {
  socket.on('data', (data) => {
    // even when debug_enabled is false, we still need this handler attached
    // so that the data is consumed from the socket buffer
    if (!debug_enabled || data.length < 20) {
      return;
    }

    const marker = data.readUInt32BE(0);
    const evType = data.readUInt8(4);
    const len = data.readUInt8(5);
    const inFd = data.readUInt32BE(8);
    const outFd = data.readUInt32BE(12);
    console.log(
      `[ipc] marker=0x${marker.toString(16)}, t=${evType} len=${len} inFd=${inFd}, outFd=${outFd}`,
    );
  });
});

// ebpf ipc marker constant (32-bit)
const MARKER = 0xbe14be14;

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

  const nodeJSEventType = 0;
  const buf = Buffer.alloc(20);
  buf.writeUInt32BE(MARKER, 0);
  buf.writeUInt8(nodeJSEventType, 4);
  buf.writeUInt8(buf.length, 5);
  buf.writeUInt8(0, 6);
  buf.writeUInt8(0, 7);
  buf.writeUInt32BE(incomingFd, 8);
  buf.writeUInt32BE(outFd, 12);
  buf.writeUInt32BE(0, 16);

  const crc = crc8(buf.slice(0, -1));
  buf.writeUInt8(crc, 19);

  if (ipcClient && ipcClient.writable) {
    ipcClient.write(buf);
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
    this === ipcClient ||
    this === ipcServer ||
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
