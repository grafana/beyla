# Args can be overriden like: docker build --build-arg DOTNET_SDK_VERSION=v1.10.0 --build-arg JAVA_SDK_VERSION=v2.20.0 ...
ARG DOTNET_SDK_VERSION=v1.11.0
ARG JAVA_SDK_VERSION=v2.26.1
ARG INJECTOR_VERSION=v0.1.0

# download the opentelemetry-injector binary for the target architecture
FROM alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11 AS download-injector-binary
ARG TARGETARCH
ARG INJECTOR_VERSION

RUN apk add --no-cache curl jq wget

RUN case ${TARGETARCH} in \
    amd64) export INJECTOR_LIB="libotelinject_amd64.so" ;; \
    arm64) export INJECTOR_LIB="libotelinject_arm64.so" ;; \
    *)     echo "architecture unsupported: ${TARGETARCH}" && exit 1 ;; \
  esac && \
  wget -q -O /libotelinject.so "https://github.com/open-telemetry/opentelemetry-injector/releases/download/${INJECTOR_VERSION}/${INJECTOR_LIB}"

# Get the Python SDK for glibc
FROM python:3.14.4-trixie@sha256:b66e615ac4aab0d74c4d665bbecafba274e0cc632094ccbe4f9c41fb13c2093a AS build-python-glibc
WORKDIR /operator-build
COPY python/requirements.txt .
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
COPY python/requirements.txt .
COPY python/build_dep_tree.sh .
COPY python/deps_analyser.py .
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install --root-user-action ignore --target . -r requirements.txt
RUN ./build_dep_tree.sh
RUN python ./deps_analyser.py
RUN rm -rf build_dep_tree.sh deps_analyser.py dependency-tree.txt .dep_tree_env
COPY python/sitecustomize.py .

# Get the OTel Java SDK
FROM alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11 AS download-java-sdk
ARG JAVA_SDK_VERSION

RUN apk add --no-cache curl unzip

RUN curl -sSfL -o opentelemetry-javaagent.jar \
    "https://github.com/open-telemetry/opentelemetry-java-instrumentation/releases/download/${JAVA_SDK_VERSION}/opentelemetry-javaagent.jar"

# Get the OTel .NET SDK
FROM alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11 AS download-dotnet-sdk
ARG DOTNET_SDK_VERSION
ARG TARGETARCH

RUN apk add --no-cache curl unzip

RUN case ${TARGETARCH} in \
    amd64) export ARCH="x64" ;; \
    arm64) export ARCH="arm64" ;; \
    *)     echo "architecture unsupported: ${TARGETARCH}" && exit 1 ;; \
  esac && \
  curl -sSfL -o dotnet-instrumentation.zip \
    "https://github.com/open-telemetry/opentelemetry-dotnet-instrumentation/releases/download/${DOTNET_SDK_VERSION}/opentelemetry-dotnet-instrumentation-linux-glibc-${ARCH}.zip" && \
    mkdir -p /glibc && \
    unzip -q dotnet-instrumentation.zip -d /glibc && \
    curl -sSfL -o dotnet-instrumentation-musl.zip \
    "https://github.com/open-telemetry/opentelemetry-dotnet-instrumentation/releases/download/${DOTNET_SDK_VERSION}/opentelemetry-dotnet-instrumentation-linux-musl-${ARCH}.zip" && \
    mkdir -p /musl && \
    unzip -q dotnet-instrumentation-musl.zip -d /musl

# Build the Node.js artifacts
# The version is hardcoded in package.json and copied from the OTel Operator
# TODO: Can we allow this to be configurable just like the JVM and .NET
FROM node:20@sha256:8f693eaa7e0a8e71560c9a82b55fd54c2ae920a2ba5d2cde28bac7d1c01c9ba5 AS build-nodejs-sdk

WORKDIR /operator-build
COPY node.js/package.json .
COPY node.js/tsconfig.json .

RUN npm install
COPY node.js/register.js .
RUN cp build/workspace/node_modules/@opentelemetry/auto-instrumentations-node/build/src/register.js \
    build/workspace/node_modules/@opentelemetry/auto-instrumentations-node/build/src/otel-register.js && \
    cp register.js build/workspace/node_modules/@opentelemetry/auto-instrumentations-node/build/src/register.js
RUN ls -al *

# build the final instrumentation image
FROM alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
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
