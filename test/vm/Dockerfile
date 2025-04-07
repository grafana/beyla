FROM golang:1.24.1-alpine

# this is the toplevel Makefile target to be invoked
# see the contents of 'startup.sh' at the end of this file
ARG target=run-integration-test-vm

RUN apk update
RUN apk add --no-cache bash
RUN apk add --no-cache openrc
RUN apk add --no-cache docker
RUN apk add --no-cache docker-compose
RUN apk add --no-cache git
RUN apk add --no-cache make
RUN apk add --no-cache agetty
RUN apk add --no-cache openssh
RUN apk add --no-cache shadow
RUN ssh-keygen -A

# the default root password is 'root'
RUN echo "root:root" | chpasswd
RUN sed -i 's/^#PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config

RUN rc-update add localmount default
RUN rc-update add docker default

# not strictly required, but useful for debugging
RUN rc-update add sshd default

# enable auto root login
RUN echo ttyS0::respawn:/sbin/agetty --autologin root ttyS0 vt100 >> /etc/inittab

RUN mkdir -p /overlay/upper/testoutput /overlay/work
RUN mkdir /build
RUN mkdir /beyla

RUN cat <<EOF >> /etc/fstab
beyla   /beyla             9p       trans=virtio,version=9p2000.L                                  0  0
overlay /build             overlay  lowerdir=/beyla,upperdir=/overlay/upper,workdir=/overlay/work  0  0
tmpfs   /tmp               tmpfs    rw,nodev,nosuid                                                0  0
devpts  /dev/pts           devpts   defaults                                                       0  0
tmpfs   /run               tmpfs    defaults,size=4G                                               0  0
testout /build/testoutput  9p       trans=virtio,version=9p2000.L                                  0  0
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

if [[ -n "$target" ]]; then
    cd /build && make $target && touch /build/testoutput/success
    poweroff
else
    echo "Entering interactive mode"
fi
EOF

RUN chmod +x /startup.sh
