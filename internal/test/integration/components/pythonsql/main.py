from fastapi import FastAPI
import os
import uvicorn
import psycopg

app = FastAPI()

DB_CONFIG = {
    "dbname": "sqltest",
    "user": "postgres",
    "password": "postgres",
    "host": "sqlserver",
    "port": "5432",
}

@app.get("/query")
async def query():
    conn = psycopg.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("SELECT * FROM accounting.contacts WHERE id = 1")
    cur.close()
    conn.close()
    return {"status": "OK"}

@app.get("/argquery")
async def argquery():
    conn = psycopg.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("SELECT * FROM accounting.contacts WHERE id = %s", (1,))
    cur.close()
    conn.close()
    return {"status": "OK"}

# Use psycopg3 + prepare=True to test prepared statements
#
# https://github.com/psycopg/psycopg/discussions/492
@app.get("/prepquery")
async def prepquery():
    conn = psycopg.connect(**DB_CONFIG)
    cur = conn.cursor()
    cur.execute("SELECT * FROM accounting.contacts WHERE id = %s", (1,), prepare=True)
    cur.close()
    conn.close()
    return {"status": "OK"}

@app.get("/error")
async def error():
    conn = psycopg.connect(**DB_CONFIG)
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM obi.nonexisting")
    except Exception:
        pass
    cur.close()
    conn.close()
    return {"status": "OK"}

if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
