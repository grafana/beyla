# download the opentelemetry-injector binary for the target architecture
FROM alpine:3.24.0@sha256:a2d49ea686c2adfe3c992e47dc3b5e7fa6e6b5055609400dc2acaeb241c829f4 AS download-injector-binary
ARG TARGETARCH

RUN apk add --no-cache curl jq wget

COPY opentelemetry-injector/version.txt .
RUN case ${TARGETARCH} in \
    amd64) export INJECTOR_LIB="libotelinject_amd64.so" ;; \
    arm64) export INJECTOR_LIB="libotelinject_arm64.so" ;; \
    *)     echo "architecture unsupported: ${TARGETARCH}" && exit 1 ;; \
  esac && \
  wget -q -O /libotelinject.so "https://github.com/open-telemetry/opentelemetry-injector/releases/download/v$(cat version.txt)/${INJECTOR_LIB}"

# Fetch the operator's Python requirements and append beyla-specific additions
FROM alpine:3.24.0@sha256:a2d49ea686c2adfe3c992e47dc3b5e7fa6e6b5055609400dc2acaeb241c829f4 AS prepare-python-deps
WORKDIR /build
RUN apk add --no-cache curl
COPY opentelemetry-operator/version.txt .
COPY python/requirements.extra.txt .
RUN OPERATOR_VERSION=$(cat version.txt) && \
    curl -sSfL "https://raw.githubusercontent.com/open-telemetry/opentelemetry-operator/v${OPERATOR_VERSION}/autoinstrumentation/python/requirements.txt" -o requirements.txt && \
    cat requirements.extra.txt >> requirements.txt

# Get the Python SDK for glibc
FROM python:3.14.4-trixie@sha256:1692046a126f2841dfec22313e9a282b697e0aeca6c25c0434b476feba618e16 AS build-python-glibc
WORKDIR /operator-build
COPY --from=prepare-python-deps /build/requirements.txt .
COPY python/build_dep_tree.sh .
COPY python/deps_analyser.py .
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install --root-user-action ignore --target . -r requirements.txt
RUN ./build_dep_tree.sh
RUN python ./deps_analyser.py
RUN rm -rf build_dep_tree.sh deps_analyser.py dependency-tree.txt .dep_tree_env
COPY python/sitecustomize.py .

# Get the Python SDK for musl
FROM python:3.14.4-alpine3.23@sha256:dd4d2bd5b53d9b25a51da13addf2be586beebd5387e289e798e4083d94ca837a AS build-python-musl
WORKDIR /operator-build
COPY --from=prepare-python-deps /build/requirements.txt .
COPY python/build_dep_tree.sh .
COPY python/deps_analyser.py .
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install --root-user-action ignore --target . -r requirements.txt
RUN ./build_dep_tree.sh
RUN python ./deps_analyser.py
RUN rm -rf build_dep_tree.sh deps_analyser.py dependency-tree.txt .dep_tree_env
COPY python/sitecustomize.py .

# Get the OTel Java SDK
FROM alpine:3.24.0@sha256:a2d49ea686c2adfe3c992e47dc3b5e7fa6e6b5055609400dc2acaeb241c829f4 AS download-java-sdk

RUN apk add --no-cache curl unzip

# Use Grafana's distro of the OpenTelemetry Java Agent
COPY java/version.txt .
RUN curl -sSfL -o opentelemetry-javaagent.jar \
    "https://github.com/grafana/grafana-opentelemetry-java/releases/download/v$(cat version.txt)/grafana-opentelemetry-java.jar"

# Get the OTel .NET SDK
FROM alpine:3.24.0@sha256:a2d49ea686c2adfe3c992e47dc3b5e7fa6e6b5055609400dc2acaeb241c829f4 AS download-dotnet-sdk
ARG TARGETARCH

RUN apk add --no-cache curl unzip

COPY opentelemetry-operator/version.txt .
RUN OPERATOR_VERSION=$(cat version.txt) && \
  VERSION="v$(curl -sSfL "https://raw.githubusercontent.com/open-telemetry/opentelemetry-operator/v${OPERATOR_VERSION}/autoinstrumentation/dotnet/version.txt")" && \
  case ${TARGETARCH} in \
    amd64) export ARCH="x64" ;; \
    arm64) export ARCH="arm64" ;; \
    *)     echo "architecture unsupported: ${TARGETARCH}" && exit 1 ;; \
  esac && \
  curl -sSfL -o dotnet-instrumentation.zip \
    "https://github.com/open-telemetry/opentelemetry-dotnet-instrumentation/releases/download/${VERSION}/opentelemetry-dotnet-instrumentation-linux-glibc-${ARCH}.zip" && \
    mkdir -p /glibc && \
    unzip -q dotnet-instrumentation.zip -d /glibc && \
    curl -sSfL -o dotnet-instrumentation-musl.zip \
    "https://github.com/open-telemetry/opentelemetry-dotnet-instrumentation/releases/download/${VERSION}/opentelemetry-dotnet-instrumentation-linux-musl-${ARCH}.zip" && \
    mkdir -p /musl && \
    unzip -q dotnet-instrumentation-musl.zip -d /musl

# Fetch the operator's Node.js package.json and merge in beyla-specific dependencies
FROM alpine:3.24.0@sha256:a2d49ea686c2adfe3c992e47dc3b5e7fa6e6b5055609400dc2acaeb241c829f4 AS prepare-nodejs-deps
WORKDIR /build
RUN apk add --no-cache curl jq
COPY opentelemetry-operator/version.txt .
COPY node.js/package.extra.json .
RUN OPERATOR_VERSION=$(cat version.txt) && \
    curl -sSfL "https://raw.githubusercontent.com/open-telemetry/opentelemetry-operator/v${OPERATOR_VERSION}/autoinstrumentation/nodejs/package.json" -o package-operator.json && \
    jq -s '.[0] + {dependencies: (.[0].dependencies + .[1].dependencies)}' \
        package-operator.json package.extra.json > package.json

# Build the Node.js artifacts
FROM node:20@sha256:8f693eaa7e0a8e71560c9a82b55fd54c2ae920a2ba5d2cde28bac7d1c01c9ba5 AS build-nodejs-sdk

WORKDIR /operator-build
COPY --from=prepare-nodejs-deps /build/package.json .
COPY node.js/tsconfig.json .

RUN npm install
COPY node.js/register.js .
RUN cp build/workspace/node_modules/@opentelemetry/auto-instrumentations-node/build/src/register.js \
    build/workspace/node_modules/@opentelemetry/auto-instrumentations-node/build/src/otel-register.js && \
    cp register.js build/workspace/node_modules/@opentelemetry/auto-instrumentations-node/build/src/register.js
RUN ls -al *

# build the final instrumentation image
FROM alpine:3.24.0@sha256:a2d49ea686c2adfe3c992e47dc3b5e7fa6e6b5055609400dc2acaeb241c829f4
COPY copy-to-volume.sh /
RUN mkdir -p /dist

# copy artifacts (distros, injector binary) from the build stages to the final image
COPY --from=download-injector-binary /libotelinject.so /dist/injector/libotelinject.so
COPY opentelemetry-injector/otelinject.conf /dist/injector/otelinject.conf
COPY --from=download-dotnet-sdk /glibc /dist/agents/dotnet/glibc
COPY --from=download-dotnet-sdk /musl /dist/agents/dotnet/musl
COPY --from=download-java-sdk /opentelemetry-javaagent.jar /dist/agents/jvm/opentelemetry-javaagent.jar
COPY --from=build-nodejs-sdk /operator-build/build/workspace/node_modules/@opentelemetry/auto-instrumentations-node/build/src/ /dist/agents/node.js/
COPY --from=build-nodejs-sdk /operator-build/node_modules /dist/agents/node.js/node_modules
COPY --from=build-python-glibc /operator-build/ /dist/agents/python/glibc
COPY --from=build-python-musl /operator-build/ /dist/agents/python/musl

WORKDIR /
CMD ["/copy-to-volume.sh"]
