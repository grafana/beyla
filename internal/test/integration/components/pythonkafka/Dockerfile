# Dockerfile that will build a container that runs python
FROM python:3.11@sha256:80d0556a9376af37548850151f0838cfa50137214fe7a2563e627c297d4811e1
EXPOSE 8080
RUN apt update
RUN pip install kafka-python
COPY main.py /main.py
CMD ["python", "main.py"]