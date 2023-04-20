from fastapi import FastAPI
import os
import uvicorn

app = FastAPI()


@app.get("/ping")
async def root():
    return "PONG!"

if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)