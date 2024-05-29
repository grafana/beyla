# Dockerfile that will build a container that runs python
FROM python:latest
EXPOSE 8080
RUN apt update
RUN pip install confluent-kafka
COPY main.py /main.py
CMD ["python", "main.py"]