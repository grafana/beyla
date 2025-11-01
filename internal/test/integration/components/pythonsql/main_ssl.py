from fastapi import FastAPI
import os
import uvicorn
import psycopg2

app = FastAPI()

conn = None

server = "sqlserver"

@app.get("/query")
async def root():
    global conn
    global server
    if conn is None:
        conn = psycopg2.connect(
            dbname="sqltest",
            user="postgres",
            password="postgres",
            host=server,
            port="5432"
        )

    cur = conn.cursor()
    cur.execute("SELECT * FROM accounting.contacts WHERE id=1")

    row = cur.fetchone()

    return row

@app.get("/argquery")
async def root():
    global conn
    global server
    if conn is None:
        conn = psycopg2.connect(
            dbname="sqltest",
            user="postgres",
            password="postgres",
            host=server,
            port="5432"
        )

    cur = conn.cursor()
    cur.execute("SELECT * FROM accounting.contacts WHERE id=%s", [1])

    row = cur.fetchone()

    return row

gCurr = None

@app.get("/prepquery")
async def root():
    global conn
    global gCurr
    global server
    if conn is None:
        conn = psycopg2.connect(
            dbname="sqltest",
            user="postgres",
            password="postgres",
            host=server,
            port="5432"
        )

    if gCurr is None:
        gCurr = conn.cursor()
        gCurr.execute(
            "prepare my_contacts as "
            "SELECT * from accounting.contacts WHERE id = $1")
    
    gCurr.execute("execute my_contacts (%s)", (1,))

    row = gCurr.fetchone()

    return row

if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
