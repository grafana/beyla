from fastapi import FastAPI
import os
import uvicorn
import redis

app = FastAPI()

conn = None
redis_cli = None

@app.get("/redis")
async def query():
    global conn
    global redis_cli
    if conn is None:
        redis_cli = redis.Redis(
            host='redis',
            port=6379,
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
    redis_cli.set('obi', 'rocks')

    # Get the value of inserted key
    return redis_cli.get('obi')


def try_redis_command(client, *args):
    try:
        return client.execute_command(*args)
    except Exception as e:
        pass


@app.get("/redis-error")
def redis_error_test():
    global conn
    global redis_cli
    if conn is None:
        redis_cli = redis.Redis(
            host='redis',
            port=6379,
            decode_responses=True
        )
        conn = redis_cli.ping()

    # Try invalid command
    try_redis_command(redis_cli, 'INVALID_COMMAND')

    # insert a key
    redis_cli.set('obi-error', 'rocks')

    # try to push to a key that is not a list
    try_redis_command(redis_cli, 'LPUSH', 'obi-error', 'rocks more')

    # try to eval a script with an invalid SHA
    try_redis_command(redis_cli, 'EVALSHA', 'INVALID_SHA', '0')
    return 'done', 200

@app.get("/redis-db")
def redis_error_test():
    db1_redis_cli = redis.Redis(
        host='redis',
        port=6379,
        decode_responses=True,
        db=1  # Use a different database
    )

    db1_redis_cli.set('obi-db-1', 'rocks')
    db1_redis_cli.get('obi-db-1')

    return 'done', 200

if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)


# Run redis server as
# docker run --name redis-srv -p 6379:6379 redis    