# Dockerfile that will build a container that runs python with FastAPI and uvicorn on port 8080
FROM python:3.14@sha256:6d58c1a9444bc2664f0fa20c43a592fcdb2698eb9a9c32257516538a2746c19a
EXPOSE 8080
RUN pip install fastapi uvicorn grpcio grpcio_tools requests
COPY main.py /main.py
COPY route_guide_db.json /route_guide_db.json
COPY route_guide_pb2_grpc.py /route_guide_pb2_grpc.py
COPY route_guide_pb2.py /route_guide_pb2.py
COPY route_guide_pb2.pyi /route_guide_pb2.pyi
COPY route_guide_resources.py /route_guide_resources.py
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]
