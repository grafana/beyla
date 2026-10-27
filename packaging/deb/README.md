# Ubuntu amd64 companion package PoC

This experimental, unpublished DEB configures Grafana Alloy 1.21.0 or newer to
collect application telemetry with Beyla, host metrics, and profiles. It is for
Ubuntu amd64 and does not install a separate Beyla executable or service.
Alloy runs as root so it can use eBPF. The package keeps its Alloy config
separate from Alloy's vendor config and refuses to take over an existing
customized Alloy installation.

For package internals and lifecycle ownership, see [the maintainer guide](IMPLEMENTATION.md).

## Build the local package

This PoC package is not published. Build a local DEB from the repository root:

```sh
packaging/deb/build-deb.sh
```

The build uses the existing multi-stage SDK image recipe and requires a
Docker-compatible container engine, `dpkg-deb`, and network access. The
`CONTAINER_ENGINE` environment variable selects a compatible engine other than
the default `docker`. The generated package is written under `dist/`.

## Install and configure

Ensure APT can provide Alloy 1.21.0 or newer, then install the local package:

```sh
sudo apt install ./dist/grafana-beyla-sdk_*.deb
```

The companion package does not configure an APT source, and it is not
available from a public package repository.

The interactive debconf setup asks for an instrumentation mode and the
following inputs:

| Input | Required value |
| --- | --- |
| Beyla discovery | Comma-separated application ports to instrument (port ranges are accepted) |
| OTLP traces and SDK metrics | Grafana Cloud OTLP/HTTP endpoint, tenant or instance ID, and token |
| Prometheus metrics | Grafana Cloud remote-write endpoint, tenant or instance ID, and token |
| Profiles | Grafana Cloud profiles endpoint, tenant or instance ID, and token |
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

## Safety

This is an experimental PoC, not a production-ready package. Use a disposable
Ubuntu amd64 system and select only controlled test services for SDK injection.
Do not use global preload or enroll production services.
