from flask import Flask, request, Response
import os
import click
import requests
import time
import json
import logging

class SimpleJsonFormatter(logging.Formatter):
    def format(self, record):
        data = {
            "message": record.getMessage(),
            "level": record.levelname
        }
        return json.dumps(data)

app = Flask(__name__)

handler = logging.StreamHandler()
handler.setFormatter(SimpleJsonFormatter())
app.logger.handlers = [handler]
app.logger.setLevel(logging.INFO)

@app.cli.command("hello")
@click.argument("name")
def create_user(name):
    print(f"Hello {name}")

@app.cli.command("migrate")
@click.argument("name")
def create_user(name):
    print(f"Nothing to migrate for {name}")

@app.route("/smoke")
def smoke():
    return Response(status=200)

@app.route("/greeting")
def ping():
    return "PONG!"

@app.route("/tracemetoo")
def traceme():
    response = requests.get("https://utestserverssl:3043/users", verify=False)
    if response.status_code == 200:
        return response.json()
    return "PONG!"

@app.route("/black_hole")
def black_hole():
    time.sleep(200000)

    return "LIGHT!"

@app.route("/users", methods=['POST'])
def users():
    content = request.json
    return content

@app.route("/bad_dns")
def bad_dns():
    try:
        requests.get("https://www.opentelemetry.invalid")
    except Exception:
        pass
    return "Invalid DNS"

@app.route("/ok_dns")
def ok_dns():
    try:
        requests.get("https://opentelemetry.io")
    except Exception:
        pass

    return "OK DNS"

@app.route("/json_logger")
def json_logger():
    log = "this is a json log"
    app.logger.info(log)
    return log

if __name__ == '__main__':
    print(f"Server running: port={8380} process_id={os.getpid()}")
    app.run(host="0.0.0.0", port=8380, debug=False)
