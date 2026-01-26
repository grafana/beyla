# Dockerfile that will build a container that runs python with FastAPI and paho-mqtt on port 8080
FROM python:3.14@sha256:17bc9f1d032a760546802cc4e406401eb5fe99dbcb4602c91628e73672fa749c
EXPOSE 8080
RUN pip install fastapi uvicorn paho-mqtt
COPY internal/test/integration/components/pythonmqtt /main
WORKDIR /main
CMD ["python", "pythonmqtt.py"]
