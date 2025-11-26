FROM python:3.12@sha256:de96c54f25e2d69597a72bd3309d723110e59586845c5675c8cb83afb808af18
EXPOSE 8080
RUN pip install ariadne fastapi uvicorn
COPY main.py /main.py
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]
