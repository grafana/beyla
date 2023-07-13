## Build and run instructions

### Installing pre-requisites

```bash
pip install flask
pip install gunicorn
```

### Running in debug mode

```bash
python main.py
```

### Running in production mode

```bash
gunicorn -w 4 -b 0.0.0.0:8080 'main:app'
```

### Running in production SSL mode

```bash
gunicorn --keyfile server.key --certfile server.crt -w 4 -b 0.0.0.0:8080 'main:app'
```