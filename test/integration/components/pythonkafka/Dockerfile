# Dockerfile that will build a container that runs python
FROM python:3.11
EXPOSE 8080
RUN apt update
RUN pip install kafka-python
COPY main.py /main.py
CMD ["python", "main.py"]