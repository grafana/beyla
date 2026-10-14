# Internal jvmtools Fork

This directory contains a minimal fork of `github.com/grafana/jvmtools` copied
from version `v0.0.5`.

Only the JVM attach code currently used by OBI is included:

- `jvm/cmd.go`
- `jvm/cmd_hotspot.go`
- `jvm/cmd_openj9.go`
- `jvm/linux_tools.go`
- `util/psutil.go`

The CLI, scripts, dynamic-agent-loading flag flip code, and ptrace/ELF helpers
are intentionally omitted. The initial copy is behavior-preserving; local
changes should remain scoped to OBI's JVM attach needs.

The attach implementation is Linux-only. Non-Linux files provide stubs so Go
package discovery and validation can still list the internal fork packages.
