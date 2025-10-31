from fastapi import FastAPI
import os
import uvicorn
from pymongo import MongoClient

app = FastAPI()

client = None

@app.get("/mongo")
async def query():
    global client
    if client is None:
        client = MongoClient("mongodb://mongo:27017/")  # or your MongoDB URI

    # Select database and collection
    db = client["mydatabase"]
    collection = db["mycollection"]

    # Insert a document
    collection.insert_one({"name": "Alice", "age": 30})

    # # Find one document
    doc = collection.find_one({"name": "Alice"})
    print(doc)

    # Update
    collection.update_one({"name": "Alice"}, {"$set": {"age": 31}})

    # Delete
    collection.delete_one({"name": "Alice"})

# TODO (mongo) add error tests + other types of requests
if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)