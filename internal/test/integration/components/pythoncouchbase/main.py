from fastapi import FastAPI
import os
import uvicorn
from datetime import timedelta
from couchbase.cluster import Cluster
from couchbase.options import ClusterOptions
from couchbase.auth import PasswordAuthenticator
from couchbase.exceptions import DocumentNotFoundException

app = FastAPI()

def get_collection():
    auth = PasswordAuthenticator("Administrator", "password")
    cluster = Cluster("couchbase://couchbase", ClusterOptions(auth))
    cluster.wait_until_ready(timedelta(seconds=30))
    bucket = cluster.bucket("test-bucket")
    return bucket.scope("test-scope").collection("test-collection")

@app.get("/couchbase")
async def query():
    coll = get_collection()

    # SET - Upsert a document
    coll.upsert("user::1", {"name": "Alice", "age": 30, "email": "alice@example.com"})

    # GET - get a document
    result = coll.get("user::1")
    print(f"GET result: {result.content_as[dict]}")

    # REPLACE - Update the document
    coll.replace("user::1", {"name": "Alice", "age": 31, "email": "alice@example.com"})

    # DELETE - Remove the document
    coll.remove("user::1")

    return {"status": "ok"}

@app.get("/couchbase-error")
async def couchbase_error():
    coll = get_collection()

    # Try to get a non-existent document - this will return KEY_NOT_FOUND
    try:
        coll.get("nonexistent::key")
    except DocumentNotFoundException:
        pass  # Expected error

    return {"status": "error_test_complete"}

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
