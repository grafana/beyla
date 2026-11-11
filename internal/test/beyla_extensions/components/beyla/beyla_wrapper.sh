#!/bin/bash

# Start the instrumenter
./beyla "$@" &
beyla_pid=$!

# Forward termination signals to beyla instead of letting bash die first.
# Without this, `docker compose stop` kills the wrapper, orphans beyla, and
# docker SIGKILLs it once the stop timeout expires, so beyla never detaches
# its probes or flushes coverage. On the peer-metadata compose the
# instrumenter shares the workload's PID namespace (pid: service:server /
# pid: service:client), so a SIGKILLed instrumenter leaves probes attached to
# a workload that is still running, and the workload container dies when the
# suite starts second-caller into that same namespace.
# shellcheck disable=SC2329 # Bash invokes this function through the signal trap below.
terminate() {
  kill -TERM "$beyla_pid" 2>/dev/null
}
trap terminate TERM INT

# `wait` is interrupted by the trap, so wait again to actually reap the child
# and pick up its real exit status.
wait "$beyla_pid"
status=$?
if [ "$status" -gt 128 ]; then
  wait "$beyla_pid"
  status=$?
fi

exit $status
