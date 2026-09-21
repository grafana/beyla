import json
import os
import urllib.request

import psycopg
from flask import Flask, jsonify

app = Flask(__name__)
database_secret = json.loads(os.environ["DB_SECRET"])


@app.get("/checkout")
def checkout():
    with urllib.request.urlopen(os.environ["LEGACY_URL"], timeout=3) as response:
        legacy = json.load(response)

    with psycopg.connect(
        host=os.environ["DB_HOST"],
        dbname=os.environ["DB_NAME"],
        user=database_secret["username"],
        password=database_secret["password"],
        sslmode="disable",
        connect_timeout=3,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            database = cursor.fetchone()[0]

    return jsonify(database=database, legacy=legacy["service"], service="checkout")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
