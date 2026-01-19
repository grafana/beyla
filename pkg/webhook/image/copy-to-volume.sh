#!/bin/sh

# The destination mount is provided externally by the mutating webhook
cp -r /dist/* /__otel_sdk_auto_instrumentation__/
