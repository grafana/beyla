const FD_MARK = Symbol.for('fdextractor.already_loaded');

if (global[FD_MARK]) {
	return;
}

global[FD_MARK] = true;

const { AsyncLocalStorage } = require('async_hooks');
const net = require('net');

const debug_enabled = false;

const ipcServer = net.createServer();
ipcServer.listen(0, '127.0.0.1', () => {
	if (!debug_enabled) return;

	const addr = ipcServer.address();
	console.log(`[ipc] server listening on ${addr.address}:${addr.port}`);
});

let ipcClient;
ipcServer.on('listening', () => {
	const { port, address } = ipcServer.address();
	ipcClient = net.connect(port, address, () => {
		ipcClient.setNoDelay(true)
		if (debug_enabled)
			console.log(`[ipc] client connected to server on ${address}:${port}`);
	});
});

ipcServer.on('connection', socket => {
	socket.on('data', data => {
		// Expect 12-byte message: [marker][inFd][outFd]
		if (!debug_enabled || data.length < 12) return;
		const marker = data.readUInt32BE(0);
		const inFd   = data.readUInt32BE(4);
		const outFd  = data.readUInt32BE(8);
		console.log(
			`[ipc] marker=0x${marker.toString(16)}, inFd=${inFd}, outFd=${outFd}`
		);
	});
});

// beyla marker constant (32-bit)
const MARKER = 0xBE14BE14;

const lastIncomingForOut = new Map();

// ALS store holds only incomingFd
const als = new AsyncLocalStorage();

const origServerEmit = net.Server.prototype.emit;
net.Server.prototype.emit = function(event, ...args) {
	if (event === 'connection') {
		const socket = args[0];
		const incomingFd = socket._handle && socket._handle.fd;

		if (debug_enabled) {
			console.log(
				`[incoming TCP] fd:${incomingFd}, remote=${socket.remoteAddress}:${socket.remotePort}`
			);
		}

		return als.run({ incomingFd }, () =>
			origServerEmit.call(this, event, ...args)
		);
	}
	return origServerEmit.call(this, event, ...args);
};

function correlate(incomingFd, outFd, socket) {
	// skip invalid or same
	if (incomingFd < 0 || outFd < 0 || incomingFd === outFd) return;

	const prev = lastIncomingForOut.get(outFd);
	if (prev === incomingFd) return;
	lastIncomingForOut.set(outFd, incomingFd);

	const addr = socket.remoteAddress || 'unknown';
	const port = socket.remotePort || 'unknown';

	if (debug_enabled) {
		console.log(
			`[outgoing TCP] inFd:${incomingFd}, outFd:${outFd}, to=${addr}:${port}`
		);
	}

	const buf = Buffer.alloc(12);
	buf.writeUInt32BE(MARKER, 0);
	buf.writeUInt32BE(incomingFd, 4);
	buf.writeUInt32BE(outFd, 8);
	if (ipcClient && ipcClient.writable) ipcClient.write(buf);
}

const origSocketConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function(...args) {
	const store = als.getStore();
	const sock = this;
	const result = origSocketConnect.apply(this, args);

	if (store) {
		sock.once('connect', () => {
			const outFd = sock._handle && sock._handle.fd;
			correlate(store.incomingFd, outFd, sock);
		});
	}

	return result;
};

const origSocketWrite = net.Socket.prototype.write;
net.Socket.prototype.write = function(data, ...rest) {
	// skip ipc writes
	if (this === ipcClient || this === ipcServer || this === process.stdout || this === process.stderr) {
		return origSocketWrite.apply(this, [data, ...rest]);
	}

	const store = als.getStore();

	if (store) {
		const outFd = this._handle && this._handle.fd;
		correlate(store.incomingFd, outFd, this);
	}

	return origSocketWrite.apply(this, [data, ...rest]);
};
