from fastapi import FastAPI
import os
import uvicorn
from datetime import timedelta
from couchbase.cluster import Cluster
from couchbase.options import ClusterOptions, QueryOptions
from couchbase.auth import PasswordAuthenticator
from couchbase.exceptions import DocumentNotFoundException, CouchbaseException

app = FastAPI()

def get_cluster():
    auth = PasswordAuthenticator("Administrator", "password")
    cluster = Cluster("couchbase://couchbase", ClusterOptions(auth))
    cluster.wait_until_ready(timedelta(seconds=30))
    return cluster

def get_collection():
    cluster = get_cluster()
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

@app.get("/sqlpp")
async def sqlpp_query():
    """Test SQL++ queries via Couchbase SDK"""
    cluster = get_cluster()

    # First, insert a document using SQL++
    insert_stmt = 'INSERT INTO `test-bucket`.`test-scope`.`test-collection` (KEY, VALUE) VALUES ("sqlpp::1", {"name": "Bob", "age": 25, "type": "sqlpp-test"})'
    result = cluster.query(insert_stmt)
    for row in result:
        print(f"INSERT result row: {row}")

    # SELECT query
    select_stmt = 'SELECT * FROM `test-bucket`.`test-scope`.`test-collection` WHERE type = "sqlpp-test"'
    result = cluster.query(select_stmt)
    for row in result:
        print(f"SELECT result row: {row}")

    # DELETE the test document
    delete_stmt = 'DELETE FROM `test-bucket`.`test-scope`.`test-collection` WHERE META().id = "sqlpp::1"'
    result = cluster.query(delete_stmt)
    for row in result:
        print(f"DELETE result row: {row}")

    return {"status": "ok"}

@app.get("/sqlpp-with-context")
async def sqlpp_query_with_context():
    """Test SQL++ queries with query_context via Couchbase SDK"""
    cluster = get_cluster()

    # Use query_context to specify the bucket and scope
    select_stmt = "SELECT * FROM `test-collection` LIMIT 1"
    result = cluster.query(
        select_stmt,
        QueryOptions(query_context="default:`test-bucket`.`test-scope`")
    )
    for row in result:
        print(f"SELECT with context result row: {row}")

    return {"status": "ok"}

@app.get("/sqlpp-error")
async def sqlpp_error():
    """Test SQL++ query that returns an error (non-existent keyspace)"""
    cluster = get_cluster()

    # Query a non-existent keyspace - this will return an error
    error_stmt = "SELECT * FROM `nonexistent-bucket`.`nonexistent-scope`.`nonexistent-collection` LIMIT 1"
    try:
        result = cluster.query(error_stmt)
        # Need to iterate to trigger the error
        for row in result:
            print(f"Unexpected result row: {row}")
    except CouchbaseException as e:
        print(f"Expected SQL++ error: {e}")

    return {"status": "error_test_complete"}

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
