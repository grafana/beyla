from flask import Flask, request, Response
import os
import click
import requests
import time

app = Flask(__name__)


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

if __name__ == '__main__':
    print(f"Server running: port={8380} process_id={os.getpid()}")
    app.run(host="localhost", port=8380, debug=False)