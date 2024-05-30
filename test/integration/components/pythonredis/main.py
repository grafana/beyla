from fastapi import FastAPI
import os
import uvicorn
import redis

app = FastAPI()

conn = None
redis_cli = None

@app.get("/query")
async def root():
    global conn
    global redis_cli
    if conn is None:
        redis_cli = redis.Redis(
            host='redis',
            port=6379,
            charset="utf-8",
            decode_responses=True
            )
        conn = redis_cli.ping()

    # Do an HSET
    redis_cli.hset('user-session:123', mapping={
        'name': 'John',
        "surname": 'Smith',
        "company": 'Redis',
        "age": 29
    })

    # GET ALL
    redis_cli.hgetall('user-session:123')

    # Set a key
    redis_cli.set('beyla', 'rocks')

    # Get the value of inserted key
    return redis_cli.get('beyla')


if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)


# Run redis server as
# docker run --name redis-srv -p 6379:6379 redis    