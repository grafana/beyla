from fastapi import FastAPI
import os
import uvicorn
import mysql.connector

app = FastAPI()

conn = None

@app.get("/query")
async def root():
    global conn
    if conn is None:
        conn = mysql.connector.connect(
            database="sakila",
            user="sakila",
            password="p_ssW0rd",
            host="sqlserver",
            port="3306"
        )

    cur = conn.cursor()
    cur.execute("SELECT * FROM actor WHERE actor_id=1")

    row = cur.fetchone()

    return row

@app.get("/argquery")
async def root():
    global conn
    if conn is None:
        conn = mysql.connector.connect(
            database="sakila",
            user="sakila",
            password="p_ssW0rd",
            host="sqlserver",
            port="3306"
        )

    cur = conn.cursor()
    cur.execute("SELECT * FROM actor WHERE actor_id=%s", [1])

    row = cur.fetchone()

    return row

gCurr = None

@app.get("/prepquery")
async def root():
    global conn
    global gCurr
    if conn is None:
        conn = mysql.connector.connect(
            database="sakila",
            user="sakila",
            password="p_ssW0rd",
            host="sqlserver",
            port="3306"
        )

    if gCurr is None:
        gCurr = conn.cursor()
        gCurr.execute(
            "PREPARE my_actors FROM 'SELECT * FROM actor WHERE actor_id = ?'"
        )    

    gCurr.execute("EXECUTE my_actors USING @actor_id", {'actor_id': 1})

    row = gCurr.fetchone()

    return row

@app.get("/error")
async def root():
    global conn
    if conn is None:
        conn = mysql.connector.connect(
            database="sakila",
            user="sakila",
            password="p_ssW0rd",
            host="sqlserver",
            port="3306"
        )

    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM obi.nonexisting")
    except Exception as e:
        conn.rollback()
    finally:
        cur.close()

    return ""

if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
