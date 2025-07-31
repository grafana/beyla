# Dockerfile that will build a container that runs python flask 7771
FROM python:3.11.6-slim
EXPOSE 7771 7772 7773 7774
RUN pip install flask gunicorn requests

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY test/integration/components/pythonselfserver .

CMD ["python", "main.py"]
