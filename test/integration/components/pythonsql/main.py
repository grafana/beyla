from fastapi import FastAPI
import os
import uvicorn
import psycopg2

app = FastAPI()

conn = psycopg2.connect(
    dbname="sqltest",
    user="postgres",
    password="postgres",
    host="localhost",
    port="5432"
)

@app.get("/query")
async def root():
    cur = conn.cursor()
    cur.execute("SELECT * from accounting.contacts WHERE id=1")

    row = cur.fetchone()

    return row


if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)