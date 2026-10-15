#!/bin/sh
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -eu

socket_gid=$(stat -c '%g' /var/run/docker.sock)
socket_group=$(getent group "$socket_gid" | cut -d: -f1)
if [ -z "$socket_group" ]; then
    socket_group="docker-$socket_gid"
    groupadd --gid "$socket_gid" "$socket_group"
fi
usermod --append --groups "$socket_group" vscode
