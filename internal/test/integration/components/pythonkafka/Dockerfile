# Dockerfile that will build a container that runs python
FROM python:3.11@sha256:df64b825ea3eff541ad1fda26620222d68824e8f3a619b76ebe4b342c4d807ff
EXPOSE 8080
RUN apt update
RUN pip install kafka-python
COPY main.py /main.py
CMD ["python", "main.py"]