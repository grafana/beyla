# Dockerfile that will build a container that runs python with FastAPI and uvicorn on port 8080
FROM python:3.12@sha256:a9841e6ccd4c0e30225a54dd133431b61325c43e20893576ffcfa7235237e444
EXPOSE 8080
RUN pip install fastapi uvicorn pymongo
COPY main.py /main.py
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]