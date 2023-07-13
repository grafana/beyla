from flask import Flask, Response
import os

app = Flask(__name__)

@app.route("/smoke")
def smoke():
    return Response(status=200)

@app.route("/greeting")
def ping():
    return "PONG!"

if __name__ == '__main__':
    print(f"Server running: port={8080} process_id={os.getpid()}")
    app.run(host="localhost", port=8080, debug=False)