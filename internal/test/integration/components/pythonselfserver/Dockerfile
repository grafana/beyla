# Dockerfile that will build a container that runs python flask 7771
FROM python:3.14.1-slim@sha256:b823ded4377ebb5ff1af5926702df2284e53cecbc6e3549e93a19d8632a1897e
EXPOSE 7771 7772 7773 7774
RUN pip install flask gunicorn requests

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/pythonselfserver .

CMD ["python", "main.py"]
