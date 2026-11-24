# download the opentelemetry-injector binary for the target architecture
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS download-injector-binary
ARG TARGETARCH
WORKDIR /

# Use the latest patched tools from the pinned Alpine base's stable repository;
# package revisions are replaced as security updates ship.
# hadolint ignore=DL3018
RUN apk add --no-cache curl jq wget

COPY opentelemetry-injector/version.txt .
RUN case ${TARGETARCH} in \
    amd64) export INJECTOR_LIB="libotelinject_amd64.so" ;; \
    arm64) export INJECTOR_LIB="libotelinject_arm64.so" ;; \
    *)     echo "architecture unsupported: ${TARGETARCH}" && exit 1 ;; \
  esac && \
  wget -q -O /libotelinject.so "https://github.com/open-telemetry/opentelemetry-injector/releases/download/v$(cat version.txt)/${INJECTOR_LIB}"

# Fetch the operator's Python requirements and append beyla-specific additions
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS prepare-python-deps
WORKDIR /build
# Keep packages current with security updates from the pinned Alpine base.
# hadolint ignore=DL3018
RUN apk add --no-cache curl
COPY opentelemetry-operator/version.txt .
COPY python/requirements.extra.txt .
RUN OPERATOR_VERSION=$(cat version.txt) && \
    curl -sSfL "https://raw.githubusercontent.com/open-telemetry/opentelemetry-operator/v${OPERATOR_VERSION}/autoinstrumentation/python/requirements.txt" -o requirements.txt && \
    cat requirements.extra.txt >> requirements.txt

FROM ruby:4.0.10-alpine3.23@sha256:24be9067c09756e3c5d8315bc1c91d069e89b122b05d0f4f01eb06d7500308ea AS prepare-ruby
WORKDIR /source
# Use the latest patched Git package from the pinned Alpine base repository.
# hadolint ignore=DL3018
RUN apk add --no-cache git
COPY ruby/upstream-revision.txt .
RUN revision=$(cat upstream-revision.txt) && \
    git init --quiet && \
    git remote add origin https://github.com/open-telemetry/opentelemetry-ruby-instrumentation.git && \
    git fetch --quiet --depth 1 origin "${revision}" && \
    test "$(git rev-parse FETCH_HEAD)" = "${revision}" && \
    git checkout --quiet --detach FETCH_HEAD && \
    gem build opentelemetry-auto-instrumentation.gemspec --output /opentelemetry-auto-instrumentation.gem

FROM ruby:4.0.10-slim-bookworm@sha256:2ae2957252f1d59985f012f876f4f70d8fc643537766499ba5efa2c991319823 AS build-ruby-glibc
WORKDIR /
# Track current Debian security revisions rather than pinning package versions
# that can disappear from the archive.
# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*
COPY --from=prepare-ruby /opentelemetry-auto-instrumentation.gem /tmp/
COPY ruby/Gemfile.lock ruby/locked_gems.rb ruby/upstream-revision.txt /tmp/
# Gem versions come from the committed lockfile and locked_gems.rb; xargs keeps
# each name/version pair as a separate argument to gem install.
RUN ruby /tmp/locked_gems.rb /tmp/Gemfile.lock > /tmp/locked-gems.txt && \
    xargs -r gem install --install-dir /operator-build --no-document --ignore-dependencies /tmp/opentelemetry-auto-instrumentation.gem < /tmp/locked-gems.txt && \
    rm /tmp/locked-gems.txt
COPY ruby/opentelemetry-auto-instrumentation.rb /operator-build/
COPY ruby/beyla /operator-build/beyla
COPY ruby/verify_bundle.rb ruby/dependency_requirements_generator.rb /tmp/
RUN ruby /tmp/verify_bundle.rb /operator-build /tmp/Gemfile.lock /tmp/upstream-revision.txt

FROM ruby:4.0.10-alpine3.23@sha256:24be9067c09756e3c5d8315bc1c91d069e89b122b05d0f4f01eb06d7500308ea AS build-ruby-musl
# Keep Alpine security updates current rather than pinning ephemeral versions.
# hadolint ignore=DL3018
RUN apk add --no-cache build-base
COPY --from=prepare-ruby /opentelemetry-auto-instrumentation.gem /tmp/
COPY ruby/Gemfile.lock ruby/locked_gems.rb ruby/upstream-revision.txt /tmp/
# Gem versions come from the committed lockfile and locked_gems.rb; xargs keeps
# each name/version pair as a separate argument to gem install.
RUN ruby /tmp/locked_gems.rb /tmp/Gemfile.lock > /tmp/locked-gems.txt && \
    xargs -r gem install --install-dir /operator-build --no-document --ignore-dependencies /tmp/opentelemetry-auto-instrumentation.gem < /tmp/locked-gems.txt && \
    rm /tmp/locked-gems.txt
COPY ruby/opentelemetry-auto-instrumentation.rb /operator-build/
COPY ruby/beyla /operator-build/beyla
COPY ruby/verify_bundle.rb ruby/dependency_requirements_generator.rb /tmp/
RUN ruby /tmp/verify_bundle.rb /operator-build /tmp/Gemfile.lock /tmp/upstream-revision.txt

# Get the Python SDK for glibc
FROM python:3.15.2-trixie@sha256:cc8e02af50fcaf0944fd02158cd77abce78eb4b41ac0217a8434bbc475225e09 AS build-python-glibc
WORKDIR /operator-build
COPY --from=prepare-python-deps /build/requirements.txt .
COPY python/build_dep_tree.sh .
COPY python/deps_analyser.py .
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
# Avoid retaining pip's download cache in this build layer.
RUN pip install --no-cache-dir --root-user-action ignore --target . -r requirements.txt
# Keep dependency-tree generation in its own layer so the expensive install
# above remains cached when the helper script changes.
# hadolint ignore=DL3059
RUN ./build_dep_tree.sh
# Keep analysis cached separately from dependency-tree generation.
# hadolint ignore=DL3059
RUN python ./deps_analyser.py
# Remove build-only helpers in a separate layer after they have been used.
# hadolint ignore=DL3059
RUN rm -rf build_dep_tree.sh deps_analyser.py dependency-tree.txt .dep_tree_env
COPY python/sitecustomize.py .
COPY python/_beyla_otel ./_beyla_otel

# Get the Python SDK for musl
FROM python:3.15.2-alpine3.23@sha256:32f06114a111c2467804d06194c5584f16804a78cfaf427fb1fcbb0b3391d0f1 AS build-python-musl
WORKDIR /operator-build
COPY --from=prepare-python-deps /build/requirements.txt .
COPY python/build_dep_tree.sh .
COPY python/deps_analyser.py .
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
# Avoid retaining pip's download cache in this build layer.
RUN pip install --no-cache-dir --root-user-action ignore --target . -r requirements.txt
# Keep dependency-tree generation in its own layer so the expensive install
# above remains cached when the helper script changes.
# hadolint ignore=DL3059
RUN ./build_dep_tree.sh
# Keep analysis cached separately from dependency-tree generation.
# hadolint ignore=DL3059
RUN python ./deps_analyser.py
# Remove build-only helpers in a separate layer after they have been used.
# hadolint ignore=DL3059
RUN rm -rf build_dep_tree.sh deps_analyser.py dependency-tree.txt .dep_tree_env
COPY python/sitecustomize.py .
COPY python/_beyla_otel ./_beyla_otel

# Get the OTel Java SDK
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS download-java-sdk
WORKDIR /

# Keep security updates in the pinned Alpine base's package set.
# hadolint ignore=DL3018
RUN apk add --no-cache curl unzip

# Use Grafana's distro of the OpenTelemetry Java Agent
COPY java/version.txt .
RUN curl -sSfL -o opentelemetry-javaagent.jar \
    "https://github.com/grafana/grafana-opentelemetry-java/releases/download/v$(cat version.txt)/grafana-opentelemetry-java.jar"

# Get the OTel .NET SDK
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS download-dotnet-sdk
ARG TARGETARCH
WORKDIR /

# Keep security updates in the pinned Alpine base's package set.
# hadolint ignore=DL3018
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
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS prepare-nodejs-deps
WORKDIR /build
# Keep security updates in the pinned Alpine base's package set.
# hadolint ignore=DL3018
RUN apk add --no-cache curl jq
COPY opentelemetry-operator/version.txt .
COPY node.js/package.extra.json .
RUN OPERATOR_VERSION=$(cat version.txt) && \
    curl -sSfL "https://raw.githubusercontent.com/open-telemetry/opentelemetry-operator/v${OPERATOR_VERSION}/autoinstrumentation/nodejs/package.json" -o package-operator.json && \
    jq -s '.[0] + {dependencies: (.[0].dependencies + .[1].dependencies)}' \
        package-operator.json package.extra.json > package.json

# Build the Node.js artifacts
FROM node:26@sha256:e18c3ccdf7d71619990b0e85639f506e2028a95410999cab24cc373cbd10e0ac AS build-nodejs-sdk

WORKDIR /operator-build
COPY --from=prepare-nodejs-deps /build/package.json .
COPY node.js/tsconfig.json .

RUN npm install
COPY node.js/*.js .
# Resolve the package export instead of relying on its internal build/src or dist layout.
# Keep the resolved entrypoint and its sibling bundles together because the
# injector wrapper patches the same utils module used by auto-instrumentation.
RUN NODE_REGISTER_FILE="$(node -p "require.resolve('@opentelemetry/auto-instrumentations-node/register')")" && \
    NODE_REGISTER_DIR="$(dirname "${NODE_REGISTER_FILE}")" && \
    mkdir -p nodejs-runtime && \
    cp -R "${NODE_REGISTER_DIR}/." nodejs-runtime/ && \
    cp "${NODE_REGISTER_FILE}" nodejs-runtime/otel-register.js && \
    cp ./*.js nodejs-runtime/
RUN ls -al -- *

# build the final instrumentation image
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
COPY copy-to-volume.sh /
RUN mkdir -p /dist

# copy artifacts (distros, injector binary) from the build stages to the final image
COPY --from=download-injector-binary /libotelinject.so /dist/injector/libotelinject.so
COPY opentelemetry-injector/otelinject.conf /dist/injector/otelinject.conf
COPY --from=download-dotnet-sdk /glibc /dist/agents/dotnet/glibc
COPY --from=download-dotnet-sdk /musl /dist/agents/dotnet/musl
COPY --from=download-java-sdk /opentelemetry-javaagent.jar /dist/agents/jvm/opentelemetry-javaagent.jar
COPY --from=build-nodejs-sdk /operator-build/nodejs-runtime/ /dist/agents/node.js/
COPY --from=build-nodejs-sdk /operator-build/node_modules /dist/agents/node.js/node_modules
COPY --from=build-python-glibc /operator-build/ /dist/agents/python/glibc
COPY --from=build-python-musl /operator-build/ /dist/agents/python/musl
COPY --from=build-ruby-glibc /operator-build/ /dist/agents/ruby/glibc
COPY --from=build-ruby-musl /operator-build/ /dist/agents/ruby/musl

WORKDIR /
CMD ["/copy-to-volume.sh"]
