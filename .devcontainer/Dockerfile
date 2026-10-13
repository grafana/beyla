FROM golang:1.27.1@sha256:512690a5660563b57d37ecc31129e7f136e831db2aed24a1dbeb8ad7380dc0fa AS go
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

COPY --from=go /usr/local/go /usr/local/go

# Include the runtime dependencies needed by the IDE backends.
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

USER vscode
CMD ["sleep", "infinity"]
