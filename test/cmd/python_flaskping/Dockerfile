# Dockerfile that will build a container that runs python flask with gunicorn on port 8080
FROM python:latest
EXPOSE 8080
RUN pip install flask gunicorn
COPY main.py /main.py
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "main:app"]