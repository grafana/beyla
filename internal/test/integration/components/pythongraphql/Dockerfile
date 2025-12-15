FROM python:3.14@sha256:595140b768992c05b096570e5ae487a02a2c6b3ae23ba33ce0fc34b99579c98e
EXPOSE 8080
RUN pip install ariadne fastapi uvicorn
COPY main.py /main.py
CMD ["uvicorn", "--port", "8080", "--host", "0.0.0.0", "main:app"]
