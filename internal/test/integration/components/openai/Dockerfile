FROM python:3.14@sha256:d18055009f327b22993de14458aa5a6bac032cdf459ea2a2e9bbdc3d3d49e4fb
EXPOSE 8080
COPY requirements.txt /requirements.txt
RUN pip install --require-hashes -r /requirements.txt
COPY main.py /main.py
CMD ["python", "main.py"]
