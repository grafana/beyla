# Dockerfile that will build a container that runs python with FastAPI and uvicorn on port 8080
FROM python:latest
EXPOSE 8080
RUN pip install fastapi uvicorn
COPY main.py /main.py
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]