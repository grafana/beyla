# Dockerfile that will build a container that runs python flask 7771
FROM python:3.14.2-slim@sha256:3955a7dd66ccf92b68d0232f7f86d892eaf75255511dc7e98961bdc990dc6c9b
EXPOSE 7771 7772 7773 7774
RUN pip install flask gunicorn requests

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/pythonselfserver .

CMD ["python", "main.py"]
