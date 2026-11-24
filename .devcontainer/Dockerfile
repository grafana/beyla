FROM golang:1.27.4@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS go
FROM ghcr.io/jdx/mise:2026.11.11@sha256:14a30b9945ea5c2fbae70d8b6be8f2c8b2456698f2a258f3f6315f7784c84676 AS mise
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

COPY --from=go /usr/local/go /usr/local/go
COPY --from=mise /usr/local/bin/mise /usr/local/bin/mise

# Include the runtime dependencies needed by the IDE backends.
# Use the current security updates from the pinned Debian base's package
# repository; individual archive package versions are ephemeral.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl docker-cli gcc git jq libc6-dev make procps sudo unzip \
    libfreetype6 libstdc++6 libxext6 libxi6 libxrender1 libxtst6 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1000 vscode \
    && useradd --uid 1000 --gid vscode --create-home --shell /bin/bash vscode \
    && echo 'vscode ALL=(root) NOPASSWD:ALL' > /etc/sudoers.d/vscode \
    && chmod 0440 /etc/sudoers.d/vscode

COPY --chmod=0755 setup-docker.sh /usr/local/bin/devcontainer-setup-docker

ENV PATH="/usr/local/go/bin:/home/vscode/go/bin:${PATH}" \
    GOPATH=/home/vscode/go \
    GOMODCACHE=/home/vscode/go/pkg/mod \
    GOCACHE=/home/vscode/.cache/go-build \
    DOCKER_HOST=unix:///var/run/docker.sock

USER 1000:1000
CMD ["sleep", "infinity"]
