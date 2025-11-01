# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

gunicorn --timeout 120 --keyfile server.key --certfile server.crt -w 1 -b 0.0.0.0:8380 -k uvicorn.workers.UvicornWorker main_ssl:app
