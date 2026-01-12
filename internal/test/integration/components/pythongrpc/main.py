from __future__ import print_function
from fastapi import FastAPI
import os
import uvicorn
import requests
import urllib3

import logging
import random
import time
import grpc
import route_guide_pb2
import route_guide_pb2_grpc
import route_guide_resources

# Disable SSL warnings for unsigned certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI()

channel = grpc.insecure_channel("grpcsrv:50051")
stub = route_guide_pb2_grpc.RouteGuideStub(channel)

count = 0

def make_route_note(message, latitude, longitude):
    return route_guide_pb2.RouteNote(
        message=message,
        location=route_guide_pb2.Point(latitude=latitude, longitude=longitude),
    )


def format_point(point):
    # not delegating in point.__str__ because it is an empty string when its
    # values are zero. In addition, it puts a newline between the fields.
    return "latitude: %d, longitude: %d" % (point.latitude, point.longitude)


def guide_get_one_feature(stub, point):
    feature = stub.GetFeature(point)
    if not feature.location:
        print("Server returned incomplete feature")
        return

    if feature.name:
        print(
            "Feature called %r at %s"
            % (feature.name, format_point(feature.location))
        )
    else:
        print("Found no feature at %s" % format_point(feature.location))


def guide_get_feature(stub):
    guide_get_one_feature(
        stub, route_guide_pb2.Point(latitude=409146138, longitude=-746188906)
    )

def guide_list_features(stub):
    rectangle = route_guide_pb2.Rectangle(
        lo=route_guide_pb2.Point(latitude=400000000, longitude=-750000000),
        hi=route_guide_pb2.Point(latitude=420000000, longitude=-730000000),
    )
    print("Looking for features between 40, -75 and 42, -73")

    features = stub.ListFeatures(rectangle)

    for feature in features:
        print(
            "Feature called %r at %s"
            % (feature.name, format_point(feature.location))
        )


def generate_route(feature_list):
    for _ in range(0, 10):
        random_feature = random.choice(feature_list)
        print("Visiting point %s" % format_point(random_feature.location))
        yield random_feature.location


def guide_record_route(stub):
    feature_list = route_guide_resources.read_route_guide_database()

    route_iterator = generate_route(feature_list)
    route_summary = stub.RecordRoute(route_iterator)
    print("Finished trip with %s points " % route_summary.point_count)
    print("Passed %s features " % route_summary.feature_count)
    print("Travelled %s meters " % route_summary.distance)
    print("It took %s seconds " % route_summary.elapsed_time)


def generate_messages():
    messages = [
        make_route_note("First message", 0, 0),
        make_route_note("Second message", 0, 1),
        make_route_note("Third message", 1, 0),
        make_route_note("Fourth message", 0, 0),
        make_route_note("Fifth message", 1, 0),
    ]
    for msg in messages:
        print("Sending %s at %s" % (msg.message, format_point(msg.location)))
        yield msg


def guide_route_chat(stub):
    responses = stub.RouteChat(generate_messages())
    for response in responses:
        print(
            "Received message %s at %s"
            % (response.message, format_point(response.location))
        )

@app.get("/query")
async def root():
    global channel
    global stub
    global count

    count = count + 1

    # Reset from time to time in case Beyla started too late
    if count > 5:
        channel = grpc.insecure_channel("grpcsrv:50051")
        stub = route_guide_pb2_grpc.RouteGuideStub(channel)

    guide_get_feature(stub)

    return "GRPC"

@app.get("/with_name")
async def with_name():
    try:
        response = requests.get("https://google.com", verify=False, timeout=10)
        print(f"Called https://google.com, status: {response.status_code}")
    except Exception as e:
        print(f"Error calling https://google.com: {e}")
    
    return {"message": "Called google.com", "endpoint": "/with_name"}

@app.get("/without_name")
async def without_name():
    try:
        response = requests.get("https://142.251.32.78", verify=False, timeout=10)
        print(f"Called https://142.251.32.78, status: {response.status_code}")
    except Exception as e:
        print(f"Error calling https://142.251.32.78: {e}")
    
    return {"message": "Called 142.251.32.78", "endpoint": "/without_name"}

@app.get("/unknown")
async def without_name():
    try:
        response = requests.get("http://8.8.8.9", verify=False, timeout=10)
        print(f"Called http://8.8.8.9, status: {response.status_code}")
    except Exception as e:
        print(f"Error calling http://8.8.8.9: {e}")
    
    return {"message": "Called 8.8.8.9", "endpoint": "/unknown"}

if __name__ == "__main__":
    print(f"Server running: port={8080} process_id={os.getpid()}")

    uvicorn.run(app, host="0.0.0.0", port=8080)