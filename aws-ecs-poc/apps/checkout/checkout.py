from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/checkout")
def checkout():
    return jsonify(service="checkout")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
