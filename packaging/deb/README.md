# Ubuntu amd64 companion package PoC

This experimental Ubuntu amd64 DEB configures Grafana Alloy 1.21.0 or newer to
collect application telemetry with Beyla, host metrics, and profiles. It is for
Ubuntu amd64 and does not install a separate Beyla executable or service.
Alloy runs as root so it can use eBPF. The package keeps its Alloy config
separate from Alloy's vendor config and refuses to take over an existing
customized Alloy installation.

For package internals and lifecycle ownership, see [the maintainer guide](IMPLEMENTATION.md).

## Build the local package

Build a local DEB from the repository root:

```sh
packaging/deb/build-deb.sh
```

Set `VERSION` to choose the package version. A leading `v` is removed, and
SemVer prerelease tags such as `v1.2.3-rc.1` become Debian versions such as
`1.2.3~rc.1`, which sort before `1.2.3`. Without `VERSION`, local builds use
`0.1.0~local1`. The release workflow builds the package from the published
release tag and attaches it as a release asset; package-repository publication
is separate.

The build uses the existing multi-stage SDK image recipe and requires a
Docker-compatible container engine, `dpkg-deb`, and network access. The
`CONTAINER_ENGINE` environment variable selects a compatible engine other than
the default `docker`. The generated package is written under `dist/`.

## Install and configure

Ensure APT can provide Alloy 1.21.0 or newer, then install the local package:

```sh
sudo apt install ./dist/beyla_*.deb
```

The companion package does not configure an APT source.

The interactive debconf setup asks for an instrumentation mode and the
following inputs:

| Input | Required value |
| --- | --- |
| Beyla discovery | Comma-separated application ports to instrument (port ranges are accepted) |
| OTLP traces and SDK metrics | Grafana Cloud OTLP/HTTP endpoint, tenant or instance ID, and token |
| Prometheus metrics | Grafana Cloud remote-write endpoint, tenant or instance ID, and token |
| Profiles | Grafana Cloud profiles endpoint, tenant or instance ID, and token |
| Fleet Management | Disabled by default; when enabled: remote configuration URL and an opaque instance ID |
| SDK services | In `sdk` mode only: comma-separated names of controlled systemd service units, such as `demo.service` |

Choose `beyla-only` to collect native Beyla telemetry, or `sdk` to opt selected
services into SDK auto-instrumentation. In `sdk` mode the package adds
package-owned injection settings only to the named service units. Only those
services receive SDK injection; installing the SDK payloads does not activate
injection for other services. Review the selected units and deliberately start
or restart only the controlled application services you intend to instrument.
The package does not restart application services. Mode changes after
installation are unsupported.
In `sdk` mode, traces come from enrolled services; native Beyla span export is
disabled, while Beyla metrics and host profiling remain enabled.

The package stores Cloud credentials in root-owned, mode-0600 files; do not
place tokens in command arguments or shell history. For unattended
installation, debconf can be preseeded through a protected input file instead
of entering values interactively. The package starts or restarts Alloy to
apply its configuration. It does not overwrite Alloy's existing vendor config
or adopt an existing customized Alloy setup.

Fleet Management enrollment is optional and defaults to off. When enabled,
the package adds a root-level Alloy `remotecfg` block using the supplied Fleet
URL and opaque instance ID; the instance ID is also used as the basic-auth
username, and the existing OTLP token is used as its password. The URL and ID
are required only when enrollment is enabled. Disabling Fleet leaves the
Fleet block and Fleet-specific environment values out of the package config.
The reused runtime token must have Fleet read permission; do not use
pipeline-write credentials.

## Safety

This is an experimental PoC, not a production-ready package. Use a disposable
Ubuntu amd64 system and select only controlled test services for SDK injection.
Do not use global preload or enroll production services.
