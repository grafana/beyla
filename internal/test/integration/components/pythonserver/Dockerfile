# Dockerfile that will build a container that runs python flask with gunicorn on port 7770
FROM python:3.11.6-slim@sha256:cc758519481092eb5a4a5ab0c1b303e288880d59afc601958d19e95b300bc86b
EXPOSE 7770
RUN pip install flask gunicorn requests
# Alternative: RUN pip install flask uwsgi

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/pythonserver .

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8380", "main:app", "--timeout", "90"]
# setting largish timeout for the workers so we can test Beyla timeouts
# CMD uwsgi --http 0.0.0.0:7770 --master -p 4 -w main:app
