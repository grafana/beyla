# Dockerfile that will build a container that runs python flask 7771
FROM python:3.11.6-slim@sha256:cc758519481092eb5a4a5ab0c1b303e288880d59afc601958d19e95b300bc86b
EXPOSE 7771 7772 7773 7774
RUN pip install flask gunicorn requests

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/pythonselfserver .

CMD ["python", "main.py"]
