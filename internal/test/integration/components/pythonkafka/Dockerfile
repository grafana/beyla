# Dockerfile that will build a container that runs python
FROM python:3.14@sha256:17bc9f1d032a760546802cc4e406401eb5fe99dbcb4602c91628e73672fa749c
EXPOSE 8080
RUN apt update
RUN pip install kafka-python
COPY main.py /main.py
CMD ["python", "main.py"]
