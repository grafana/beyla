FROM ghcr.io/open-telemetry/obi-testimg:python-0.1.1@sha256:83790451337767ce21b8e6c21f9fae4a1a0d1261b65097f875fdb794c7c151fd

RUN cp /usr/local/bin/python /python
COPY internal/test/integration/components/local-process/main.py /local-process.py
ENTRYPOINT ["/python", "/local-process.py"]
