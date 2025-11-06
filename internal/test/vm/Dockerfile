FROM golang:1.25.1-alpine@sha256:b6ed3fd0452c0e9bcdef5597f29cc1418f61672e9d3a2f55bf02e7222c014abd

# this is the toplevel Makefile target to be invoked
# see the contents of 'startup.sh' at the end of this file
ARG target=run-integration-test-vm
ARG test_pattern=TestMultiProcess
ARG run_number=1

RUN apk update && apk add --no-cache \
    agetty \
    bash \
    docker \
    docker-compose \
    git \
    make \
    openrc \
    openssh \
    shadow

RUN ssh-keygen -A && \
    echo "root:root" | chpasswd && \
    sed -i 's/^#PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    rc-update add localmount default && \
    rc-update add docker default && \
    rc-update add sshd default && \
    echo ttyS0::respawn:/sbin/agetty --autologin root ttyS0 vt100 >> /etc/inittab && \
    mkdir -p /overlay/upper/testoutput /overlay/work /build /beyla /precompiled-tests

# Configure Docker to relax procfs security checks.
# Ref: CVE-2025-31133, CVE-2025-52565, and CVE-2025-52881.
RUN mkdir -p /etc/docker && cat <<EOF > /etc/docker/daemon.json
{
  "features": {
    "containerd-snapshotter": false
  }
}
EOF

# Set environment variable to allow runc to run with VM procfs
RUN cat <<EOF > /etc/conf.d/docker
RUNC_ALLOW_UNSAFE_PROCFS=1
EOF

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
