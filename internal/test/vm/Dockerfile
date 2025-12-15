FROM alpine:3.20

# this is the toplevel Makefile target to be invoked
# see the contents of 'startup.sh' at the end of this file
ARG target=run-integration-test-vm
ARG test_pattern=TestMultiProcess
ARG run_number=1
ARG GO_VERSION=1.25.3

# Pin Docker/runc to Alpine 3.20 versions (before November 2025 CVE patches)
# The procfs security checks in newer runc (CVE-2025-52881, CVE-2025-52565,
# CVE-2025-31133) prevent containers from starting in nested virtualization.
# Even buildkit containers fail to boot, so insecure buildx approach is not viable.
RUN apk update && \
    apk add --no-cache \
    agetty \
    bash \
    ca-certificates \
    docker \
    docker-cli-compose \
    git \
    make \
    openrc \
    openssh \
    shadow \
    wget

# Install desired Go version
RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz && \
    ln -s /usr/local/go/bin/go /usr/bin/go && \
    ln -s /usr/local/go/bin/gofmt /usr/bin/gofmt && \
    go version

RUN ssh-keygen -A && \
    echo "root:root" | chpasswd && \
    sed -i 's/^#PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    rc-update add localmount default && \
    rc-update add docker default && \
    rc-update add sshd default && \
    echo ttyS0::respawn:/sbin/agetty --autologin root ttyS0 vt100 >> /etc/inittab && \
    mkdir -p /overlay/upper/testoutput /overlay/work /build /beyla /precompiled-tests

RUN cat <<EOF >> /etc/fstab
beyla        /beyla             9p      trans=virtio,version=9p2000.L                                  0  0
overlay      /build             overlay lowerdir=/beyla,upperdir=/overlay/upper,workdir=/overlay/work  0  0
tmpfs        /tmp               tmpfs   rw,nodev,nosuid                                                0  0
devpts       /dev/pts           devpts  defaults                                                       0  0
tmpfs        /run               tmpfs   defaults,size=4G                                               0  0
testout      /build/testoutput  9p      trans=virtio,version=9p2000.L                                  0  0
precompiled  /precompiled-tests 9p      trans=virtio,version=9p2000.L                                  0  0
EOF

RUN echo beyla > /etc/hostname

RUN cat <<EOF > /etc/network/interfaces
auto eth0
iface eth0 inet dhcp

auto lo
iface lo inet loopback
EOF

RUN rc-update add networking default

RUN cat <<EOF > /etc/init.d/startup
#!/sbin/openrc-run

command="sh /startup.sh"
EOF

RUN chmod +x /etc/init.d/startup

# comment out this line to get a prompt instead
# of running the tests when the VM starts
RUN rc-update add startup default

RUN cat <<EOF > /startup.sh
#!/bin/sh

export PATH=$PATH:/usr/local/go/bin

# Fix Git ownership issues
git config --global --add safe.directory /build

# Wait for Docker service to be ready
while ! docker info >/dev/null 2>&1; do
    echo "Waiting for Docker daemon to start..."
    sleep 1
done
echo "Docker daemon is ready"

# Verify runc version
echo "=== Docker/runc versions in VM ==="
docker version
runc --version
echo "=================================="

if [[ -n "$target" ]]; then
    echo "=== Starting test execution ==="
    echo "Current directory: $(pwd)"

    # Set project directory for pre-compiled binaries
    export TEST_PROJECT_DIR=/build

    cd /build && make $target TEST_PATTERN="$test_pattern" RUN_NUMBER="$run_number" && touch /build/testoutput/success
    poweroff
else
    echo "Entering interactive mode"
fi
EOF

RUN chmod +x /startup.sh
