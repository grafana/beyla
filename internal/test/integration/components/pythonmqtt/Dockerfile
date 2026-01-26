# Dockerfile that will build a container that runs python with FastAPI and paho-mqtt on port 8080
FROM python:3.14@sha256:6d58c1a9444bc2664f0fa20c43a592fcdb2698eb9a9c32257516538a2746c19a
EXPOSE 8080
RUN pip install fastapi uvicorn paho-mqtt
COPY internal/test/integration/components/pythonmqtt /main
WORKDIR /main
CMD ["python", "pythonmqtt.py"]
