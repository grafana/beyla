# Dockerfile that will build a container that runs python
FROM python:3.11@sha256:38639aa0267125ab0def2778f0aa8453043178ec67bf494c5af11f75a8392d9d
EXPOSE 8080
RUN apt update
RUN pip install kafka-python
COPY main.py /main.py
CMD ["python", "main.py"]