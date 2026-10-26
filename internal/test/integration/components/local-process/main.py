import multiprocessing
import os
import signal
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


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


if __name__ == "__main__":
    if "--idle" in sys.argv:
        signal.pause()
    else:
        server = HTTPServer(("0.0.0.0", 8080), WorkerHandler)
        context = multiprocessing.get_context("fork")
        workers = [context.Process(target=serve, args=(server,)) for _ in range(3)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
