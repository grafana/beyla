from fastapi import FastAPI, Request
import os
import uvicorn
import boto3

ENDPOINT_URL = "http://localstack:4566"
AWS_ACCESS_KEY_ID = "test"
AWS_SECRET_ACCESS_KEY = "test"
REGION = "us-east-1"
BUCKET_NAME = "obi-bucket"

def new_aws_client(service):
    return boto3.client(
        service,
        endpoint_url=ENDPOINT_URL,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=REGION
    )

s3 = new_aws_client("s3")
sqs = new_aws_client("sqs")

app = FastAPI()

@app.get("/health")
async def health():
    return "ok!"

### S3 Operations ###

@app.get("/createbucket")
async def createbucket():
    return s3.create_bucket(Bucket=BUCKET_NAME)

@app.get("/createobject")
async def createobject():
    return s3.put_object(
        Bucket=BUCKET_NAME,
        Key="hello.txt",
        Body="Hello from OBI!"
    )

@app.get("/listobjects")
async def listobjects():
    return s3.list_objects_v2(Bucket=BUCKET_NAME)

@app.get("/deleteobject")
async def deleteobject():
    return s3.delete_object(
        Bucket=BUCKET_NAME,
        Key="hello.txt"
    )

@app.get("/deletebucket")
async def deletebucket():
    return s3.delete_bucket(Bucket=BUCKET_NAME)

### SQS Operations ###

@app.get("/createqueue")
async def createqueue():
    return sqs.create_queue(QueueName="obi-queue")

@app.get("/sendmessage")
async def sendmessage(request: Request):
    queue_url = request.query_params.get("queue_url")
    return sqs.send_message(QueueUrl=queue_url, MessageBody="Hello from OBI!")

@app.get("/receivemessages")
async def receivemessages(request: Request):
    queue_url = request.query_params.get("queue_url")
    return sqs.receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=3,
    )

@app.get("/deletemessage")
async def deletemessage(request: Request):
    queue_url = request.query_params.get("queue_url")
    receipt_handle = request.query_params.get("receipt_handle")
    return sqs.delete_message(
        QueueUrl=queue_url,
        ReceiptHandle=receipt_handle,
    )

@app.get("/getqueueattributes")
async def getqueueattributes(request: Request):
    queue_url = request.query_params.get("queue_url")
    return sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["All"]
    )

@app.get("/deletequeue")
async def deletequeue(request: Request):
    queue_url = request.query_params.get("queue_url")
    return sqs.delete_queue(QueueUrl=queue_url)


if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")
    uvicorn.run(app, host="0.0.0.0", port=8080)
