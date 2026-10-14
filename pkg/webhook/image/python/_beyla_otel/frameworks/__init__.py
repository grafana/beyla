"""Python framework launch parsers."""

from .celery import parse_celery
from .common import classify_target, clean_value, target_name, target_reference
from .daphne import parse_daphne
from .django import parse_django
from .fastapi import parse_fastapi
from .flask import parse_flask
from .gunicorn import parse_gunicorn
from .hypercorn import parse_hypercorn
from .uvicorn import parse_uvicorn
from .uwsgi import parse_uwsgi
from .waitress import parse_waitress


PARSERS = {
    "gunicorn": parse_gunicorn,
    "uvicorn": parse_uvicorn,
    "hypercorn": parse_hypercorn,
    "daphne": parse_daphne,
    "uwsgi": parse_uwsgi,
    "waitress": parse_waitress,
    "waitress-serve": parse_waitress,
    "waitress_serve": parse_waitress,
    "flask": parse_flask,
    "fastapi": parse_fastapi,
    "django": parse_django,
    "django-admin": parse_django,
    "django_admin": parse_django,
    "celery": parse_celery,
}

