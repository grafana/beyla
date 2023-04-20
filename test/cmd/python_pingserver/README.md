## Build and run instructions

### Installing pre-requisites

```bash
pip install fastapi uvicorn
```

### Running

```bash
python main.py
```

### Running in SSL mode

```bash
uvicorn --ssl-keyfile server.key --ssl-certfile server.crt --port 8080 main:app
```