from flask import Flask
import os

app = Flask(__name__)

@app.route("/ping")
def ping():
    return "PONG!"

if __name__ == '__main__':
    print(f"Server running: port={8080} process_id={os.getpid()}")
    app.run(host="localhost", port=8080, debug=False)