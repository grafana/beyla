#!/bin/bash

# Mount debugfs, we should be running privileged, so should be doable
mount -t debugfs nodev /sys/kernel/debug

# Start the trace pipe reader
cat /sys/kernel/debug/tracing/trace_pipe &

# Start the instrumenter
./beyla "$@" &

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?
