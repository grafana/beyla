#!/bin/sh
set -eu

# Proxy the daemon socket without changing its host permissions or depending
# on the host's docker group ID. This script runs via sudo at container startup.
if [ ! -S /var/run/docker-host.sock ]; then
    echo 'Docker socket is missing at /var/run/docker-host.sock; recreate the dev container with its socket mount.' >&2
    exit 1
fi

if curl --silent --fail --unix-socket /var/run/docker.sock http://localhost/_ping >/dev/null 2>&1; then
    exit 0
fi

rm -f /var/run/docker.sock
nohup socat \
    UNIX-LISTEN:/var/run/docker.sock,fork,user=vscode,group=vscode,mode=0600 \
    UNIX-CONNECT:/var/run/docker-host.sock \
    </dev/null >/tmp/beyla-docker-proxy.log 2>&1 &

attempt=0
while [ "$attempt" -lt 50 ]; do
    if curl --silent --fail --unix-socket /var/run/docker.sock http://localhost/_ping >/dev/null 2>&1; then
        exit 0
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done

echo 'Docker socket proxy failed to start; see /tmp/beyla-docker-proxy.log.' >&2
exit 1
