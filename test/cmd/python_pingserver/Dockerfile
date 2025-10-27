# Dockerfile that will build a container that runs python with FastAPI and uvicorn on port 8080
FROM python:latest@sha256:78ad0471881f0232093c9e6edf58addade7bf106377732e0790c0f0c914b3b7b
EXPOSE 8080
RUN pip install fastapi uvicorn
COPY main.py /main.py
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]