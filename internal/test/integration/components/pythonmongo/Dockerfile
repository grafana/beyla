# Dockerfile that will build a container that runs python with FastAPI and uvicorn on port 8080
FROM python:3.12@sha256:2b075cba87fcf51f14e6be18f83f209fb2013d72362ec874aed7d01933253e8b
EXPOSE 8080
RUN pip install fastapi uvicorn pymongo
COPY main.py /main.py
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]