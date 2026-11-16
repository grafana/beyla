import multiprocessing
import os
import signal
import socket
import sys
import time
from contextlib import closing
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import UnixStreamServer

UNIX_SOCKET = "/sockets/http.sock"


class WorkerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Identify the worker process handling this request."""
        body = str(os.getpid()).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(server):
    """Handle HTTP requests using the listener inherited from the parent."""
    server.serve_forever()


class UnixWorkerHandler(WorkerHandler):
    def address_string(self):
        return "unix-client"


class UnixHTTPConnection(HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(UNIX_SOCKET)


def wait_for_unix_start():
    """Keep workers and client idle until Beyla's socket watcher is running."""
    while not os.path.exists("/sockets/start"):
        time.sleep(0.1)


def unix_client():
    wait_for_unix_start()
    while True:
        try:
            with closing(UnixHTTPConnection("unix-server", timeout=2)) as connection:
                connection.request("GET", "/unix-only")
                response = connection.getresponse()
                body = response.read()
                if response.status != 200 or not body.isdigit():
                    raise RuntimeError(f"unexpected Unix HTTP response: {response.status} {body!r}")
        except (OSError, HTTPException) as error:
            print(error, flush=True)
        time.sleep(0.1)


if __name__ == "__main__":
    if "--idle" in sys.argv:
        signal.pause()
    elif "--unix-client" in sys.argv:
        unix_client()
    else:
        if "--unix-server" in sys.argv:
            server = UnixStreamServer(UNIX_SOCKET, UnixWorkerHandler)
            wait_for_unix_start()
        else:
            server = HTTPServer(("0.0.0.0", 8080), WorkerHandler)
        context = multiprocessing.get_context("fork")
        workers = [context.Process(target=serve, args=(server,)) for _ in range(3)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
