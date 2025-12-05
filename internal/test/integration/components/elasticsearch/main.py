from fastapi import FastAPI, HTTPException, Request
import os
import uvicorn
import requests
import json
import time
import sys

app = FastAPI()
HEADERS = {'Content-Type': 'application/json'}

@app.get("/health")
async def health(request: Request):
    host_url = request.query_params.get("host_url")
    if host_url is None:
        raise HTTPException(
            status_code=400, 
            detail="The 'host_url' query parameter is required."
        )
    server_url = host_url + "/_cluster/health"
    try:
        response = requests.get(server_url, timeout=5)
        response.raise_for_status() 
        status = response.json().get("status", "red")
        
        if status in ("red","yellow"):
            raise HTTPException(
                status_code=503, 
                detail={"status": "red","message": "Cluster unhealthy"})
        return {"status": status, "message": "Cluster healthy"}

    except requests.RequestException as e:
        raise HTTPException(
            status_code=503, 
            detail={"status": "error","message": f"Cannot reach Cluster: {str(e)}"})

@app.get("/doc")
async def doc(request: Request):
    host_url = request.query_params.get("host_url")
    if host_url is None:
        raise HTTPException(
            status_code=400, 
            detail="The 'host_url' query parameter is required."
        )
    server_url = host_url + "/test_index/_doc/1"
    
    try:
        response = requests.get(server_url, headers=HEADERS)

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    return {"status": "OK"}


@app.get("/search")
async def search(request: Request):
    host_url = request.query_params.get("host_url")
    if host_url is None:
        raise HTTPException(
            status_code=400, 
            detail="The 'host_url' query parameter is required."
        )
    server_url = host_url + "/test_index/_search"
    query_body = {
        "query": {
            "match": {
                "name": "OBI"
                }
            }
        }
    try:
        response = requests.post(server_url, json=query_body, headers=HEADERS)

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    return {"status": "OK"}

@app.get("/msearch")
async def msearch(request: Request):
    host_url = request.query_params.get("host_url")
    if host_url is None:
        raise HTTPException(
            status_code=400, 
            detail="The 'host_url' query parameter is required."
        )
    server_url = host_url + "/_msearch"
    searches = [
        {},
        {
            "query": {
                "match": {
                    "message": "this is a test"
                }
            }
        },
        {
            "index": "my-index-000002"
        },
        {
            "query": {
                "match_all": {}
            }
        }
    ]
    try:
        response = requests.post(server_url, json=searches, headers=HEADERS)

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    return {"status": "OK"}


@app.get("/bulk")
async def bulk(request: Request):
    host_url = request.query_params.get("host_url")
    if host_url is None:
        raise HTTPException(
            status_code=400, 
            detail="The 'host_url' query parameter is required."
        )
    server_url = host_url + "/_bulk"
    actions=[
        {
            "index": {
                "_index": "test",
                "_id": "1"
            }
        },
        {
            "field1": "value1"
        },
        {
            "delete": {
                "_index": "test",
                "_id": "2"
            }
        },
        {
            "create": {
                "_index": "test",
                "_id": "3"
            }
        },
        {
            "field1": "value3"
        },
        {
            "update": {
                "_id": "1",
                "_index": "test"
            }
        },
        {
            "doc": {
                "field2": "value2"
            }
        }
    ]
    try:
        response = requests.post(server_url, json=actions, headers=HEADERS)

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    return {"status": "OK"}


if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
