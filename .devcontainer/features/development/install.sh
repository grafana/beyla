#!/bin/sh
set -eu

# VS Code Server, JetBrains backend, CGO and debugger dependencies.
apk add --no-cache \
    ca-certificates build-base linux-headers libstdc++ \
    gcompat procps libxext libxrender libxtst libxi freetype fontconfig \
    openssh-client sudo docker-cli docker-cli-compose docker-cli-buildx socat

adduser -D -s /bin/bash vscode
printf 'vscode ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/vscode
chmod 0440 /etc/sudoers.d/vscode
mkdir -p /home/vscode/.cache/go-build /go/pkg

# Login shells read /etc/profile.d; interactive non-login Bash reads .bashrc.
cp go-env.sh /etc/profile.d/beyla-go.sh
printf '\n. /etc/profile.d/beyla-go.sh\n' >> /home/vscode/.bashrc

cp docker-start.sh /usr/local/bin/beyla-docker-start
chmod 0755 /usr/local/bin/beyla-docker-start

# Install outside the generator's Go module. Use current tools so they support
# the Go version selected by generator.Dockerfile, including after Go upgrades.
cd /tmp
# Some clients apply containerEnv during the feature build. Keep root's tool
# builds out of the runtime user's GOCACHE, even when it is already configured.
export GOCACHE=/root/.cache/go-build
GOBIN=/go/bin go install golang.org/x/tools/gopls@latest
GOBIN=/go/bin go install github.com/go-delve/delve/cmd/dlv@latest
chown -R vscode:vscode /home/vscode /go
