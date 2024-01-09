"""
License: MIT License
Copyright (c) 2023 Miel Donkers
https://gist.github.com/mdonkers/63e115cc0c79b4f6b8b3a6b797e485c7

Very simple HTTP server in python for logging requests
Usage::
    ./server.py [<port>]
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging


class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        logging.info("received request %s\n", str(self.path))
        self._set_response()
        self.wfile.write("Hello!".format(self.path).encode('utf-8'))


def run(server_class=HTTPServer, handler_class=S, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Listening on http://localhost:8080\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')


if __name__ == '__main__':
    run()
