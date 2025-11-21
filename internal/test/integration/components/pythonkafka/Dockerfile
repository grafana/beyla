# Dockerfile that will build a container that runs python
FROM python:3.11@sha256:a3f963d22cc2bd1b0e9a62c8e6f31b3bd3340d554fae00cc312c3359b61a6d7e
EXPOSE 8080
RUN apt update
RUN pip install kafka-python
COPY main.py /main.py
CMD ["python", "main.py"]