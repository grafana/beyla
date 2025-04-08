# Dockerfile that will build a container that runs python flask 8081
FROM python:3.11.6-slim
EXPOSE 8081 8082 8083 8084
RUN pip install flask gunicorn requests

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY test/integration/components/pythonselfserver .

CMD ["python", "main.py"]