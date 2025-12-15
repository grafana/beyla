# Dockerfile that will build a container that runs python
FROM python:3.14@sha256:595140b768992c05b096570e5ae487a02a2c6b3ae23ba33ce0fc34b99579c98e
EXPOSE 8080
RUN apt update
RUN pip install kafka-python
COPY main.py /main.py
CMD ["python", "main.py"]