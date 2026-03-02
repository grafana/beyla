FROM beyla-oci-payload:dev AS payload

FROM alpine:3.21

RUN apk add --no-cache jq coreutils

COPY bin/oci-runtime /assets/beyla-oci-runtime
COPY --from=payload /dist /payload-dist
COPY pkg/ocihook/bootstrap/bootstrap.sh /bootstrap.sh

ENTRYPOINT ["/bootstrap.sh"]
