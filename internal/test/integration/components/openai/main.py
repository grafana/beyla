from fastapi import FastAPI, Request
import os
import uvicorn
import requests

app = FastAPI()

OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "http://localhost:8081")

@app.get("/health")
async def health():
    return "ok!"

@app.get("/messages")
async def messages():
    payload = {
        "input": "How do I check if a Python object is an instance of a class?",
        "instructions": "You are a coding assistant that talks like a pirate.",
        "model": "gpt-5-mini",
    }
    resp = requests.post(f"{OPENAI_BASE_URL}/v1/responses", json=payload)
    resp.raise_for_status()
    return resp.json()

@app.get("/error")
async def error_messages():
    payload = {
        "input": "How do I check if a Python object is an instance of a class?",
        "instructions": "You are a coding assistant that talks like a pirate.",
        "model": "gpt-5-mini",
    }
    resp = requests.post(f"{OPENAI_BASE_URL}/v1/responses?error", json=payload)
    return resp.json()

@app.get("/embeddings")
async def embeddings():
    payload = {
        "input": "The food was delicious",
        "model": "text-embedding-3-small",
        "dimensions": 256,
    }
    resp = requests.post(f"{OPENAI_BASE_URL}/v1/embeddings", json=payload)
    resp.raise_for_status()
    return resp.json()

@app.get("/chat")
async def createobject():
    payload = {
        "messages": [
            {"role": "system", "content": "You are a helpful travel assistant."},
            {"role": "user", "content": "Plan a 6-day luxury trip to London for 3 people with a $4400 budget."},
        ],
        "model": "gpt-4o-mini",
        "temperature": 0.7,
    }
    resp = requests.post(f"{OPENAI_BASE_URL}/v1/chat/completions", json=payload)
    resp.raise_for_status()
    return resp.json()

@app.get("/conversations")
async def conversations():
    payload = {
        "items": [
            {"type":"message","role":"user","content":"Hello! I am learning Python and need some guidance."}
        ],
        "metadata": {"topic":"python-help","user":"nino"},
        "model": "gpt-5-mini",
    }
    resp = requests.post(f"{OPENAI_BASE_URL}/v1/conversations", json=payload)
    resp.raise_for_status()
    return resp.json()

if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
