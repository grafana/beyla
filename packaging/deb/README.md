# Ubuntu amd64 companion package PoC

This directory contains an experimental, unpublished Ubuntu amd64 companion
DEB. It depends on Grafana Alloy; it does not install a Beyla executable or a
separate Beyla service. Alloy's `beyla.ebpf` component is configured to collect
host application telemetry. A separate `pyroscope.ebpf` component collects
profiles and `prometheus.exporter.unix` collects host metrics.

The package also carries the five SDK auto-instrumentation payloads from
`pkg/webhook/image`. Payload installation does not activate injection. SDK
mode is opt-in and limited to the explicit systemd service names supplied at
configuration time. The package writes drop-ins only for those services; it
does not use `/etc/ld.so.preload`, restart application services, or overwrite
`/etc/alloy/config.alloy`. Review the generated drop-ins and restart only the
controlled demo services yourself.

## Build

Builds use the existing multi-stage SDK image recipe; they do not copy its
artifact download/build steps into packaging code:

```sh
packaging/deb/build-deb.sh
```

The script defaults to the Docker-compatible `docker` CLI and accepts
`CONTAINER_ENGINE` to select another compatible CLI. It requires that engine,
`dpkg-deb`, and network access for the existing image build. It stages the
image's `/dist` tree and creates an unpublished `.deb` under `dist/`. Ubuntu
amd64 is the only intended target, and the DEB requires Alloy 1.21.0 or newer.
The Alloy config was validated with Alloy 1.21.2 (Linux amd64) in a
disposable Ubuntu 24.04.5 KVM guest. Package
install/configure, service startup, SDK enrollment, and removal lifecycle
were exercised there; package unit and mocked maintainer-script tests are also
included.

## Install-time configuration

The package uses debconf prompts, so it can also be preseeded for unattended
installation. Provide the three Grafana Cloud endpoints, tenant/instance IDs,
and tokens before `apt install ./dist/grafana-beyla-sdk_*.deb`. Select either
`beyla-only` or `sdk` mode. In `sdk` mode, provide a comma-separated list of
controlled systemd service unit names (for example, `demo.service`). The
configuration script rejects unsafe names and modified pre-existing drop-ins
rather than overwriting them. Preseed password values through a protected
debconf input channel; never put credentials in package build arguments or
shell command-line arguments.

The resulting Alloy environment file is root-owned mode `0600` and contains
the persistent credentials. The Alloy drop-in sets `User=root` and selects
the package-owned complete config at
`/etc/grafana/beyla-sdk/config.alloy`; Alloy's vendor config is left intact.
Package scripts validate the complete Alloy configuration and start or
restart the Alloy collector so the one-command installation is usable. They
never restart an application. Review each selected service drop-in and
start/restart only controlled workloads yourself. Changing SDK mode through
`dpkg-reconfigure` is intentionally unsupported in this PoC; edit persistent
root-only endpoint credentials directly and arrange a deliberate Alloy restart
for credential rotation.

SDK mode sets `LD_PRELOAD` and the injector config path only for selected
services. This is a narrow PoC enrollment mechanism, not general host-wide
injection support. It does not safely identify every application and does not
automatically restart an already running process. Start/restart only a
controlled workload after reviewing its drop-in. Beyla-only mode creates no
application drop-ins. SDK mode turns off Beyla span export globally to avoid
duplicate spans; only explicitly enrolled services emit SDK spans in that
mode. Beyla metrics and host profiling remain enabled.

## Safety / status

Do not install this PoC on a production host or experiment with global preload.
A disposable Ubuntu 24.04.5 KVM guest (`query-kvm` reported enabled) with Alloy
1.21.2 and a guest-local Docker-LGTM backend was used for an end-to-end smoke.
The Beyla-only mode produced a native Go workload trace and RED metric; the
host Unix metric was present, and Pyroscope returned a non-empty CPU profile
with the `main.rolldice` frame. In SDK mode, package-only `LD_PRELOAD` enrollment
produced stored Tempo traces for controlled Java 21, .NET 10, Node.js 18,
Python 3.12, and CRuby 3.3.12 services. Ruby used Sinatra/Puma dependencies but
no manual OTel SDK bootstrap. Test-only synthetic tenant/token values were used
with local endpoints; no Grafana Cloud credentials or requests were involved.
The detailed test evidence and rebuilt DEB are retained locally under
`dist/kvm-results/2026-10-26-ubuntu2404-lgtm-sdk-smoke/`; those generated
artifacts are intentionally excluded from this PR.

This is a bounded single-guest smoke, not release qualification: it does not
cover production hardening, customer-specific applications, a broad OS/Alloy
upgrade matrix, profile/trace correlation, or Grafana Cloud auth/acceptance.
This PR does not publish the package to Grafana APT and does not imply
release readiness.
