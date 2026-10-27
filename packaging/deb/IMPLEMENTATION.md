# Debian package implementation notes

This guide is for maintainers of the experimental Ubuntu amd64 companion
package. User-facing installation and configuration instructions are in
[README.md](README.md). The package configures Alloy; it does not install a
standalone Beyla service.

## Ownership and installed layout

The package deliberately keeps its complete Alloy configuration separate from
Alloy's vendor configuration:

| Source in this repository | Installed path | Purpose |
| --- | --- | --- |
| `alloy-config.alloy` | `/usr/share/grafana-beyla-sdk/config.alloy` (package-owned template) and, on first configure, `/etc/grafana/beyla-sdk/config.alloy` (active copy) | Complete package-owned Alloy config selected by the package service drop-in |
| `alloy-dropin.conf` | `/usr/share/grafana-beyla-sdk/alloy-service-dropin.conf` | Source for `/etc/systemd/system/alloy.service.d/50-grafana-beyla-sdk.conf`; sets `User=root` and `EnvironmentFile=/etc/grafana/beyla-sdk/alloy.env` |
| `configure.py` | `/usr/lib/grafana-beyla-sdk/configure.py` | Validates debconf values and selected units, writes persistent settings and optional service drop-ins |
| `validate-alloy.py` | `/usr/lib/grafana-beyla-sdk/validate-alloy.py` | Validates the active complete Alloy config before starting or restarting Alloy |
| SDK image `/dist` tree | `/opt/grafana/beyla-sdk/dist/` | Bundled injection library and language agents/configuration |

The active Alloy drop-in is the only package-owned Alloy service override. It
selects the complete package config through `CONFIG_FILE` in `alloy.env`; it
does not edit `/etc/alloy/config.alloy`, append to that vendor file, or change
Alloy's own package defaults. Before first adoption, `postinst` accepts only
the pristine `/etc/default/alloy`, the checksum-matching vendor
`/etc/alloy/config.alloy`, and no existing Alloy service drop-ins. An existing
customized Alloy installation is rejected rather than adopted. The package
also refuses unmarked pre-existing files at its config destination.

The package owns `/var/lib/grafana-beyla-sdk/mode` and, in SDK mode,
`/var/lib/grafana-beyla-sdk/services` as its configuration state markers. The
persistent Alloy environment is `/etc/grafana/beyla-sdk/alloy.env`; SDK
enrollment settings are in `/etc/grafana/beyla-sdk/sdk.env`. Both are written
atomically as root-only mode `0600`. Configuration input is checked for
required values and unsafe/missing service names before these durable secrets
or the state marker are created. Password values are cleared from debconf
after successful initial configuration.

## SDK payload and enrollment

`build-deb.sh` obtains the payload by building the canonical multi-stage
`pkg/webhook/image/Dockerfile` and staging its `/dist` output. Keep artifact
downloads/build steps in that existing image recipe rather than duplicating
them in packaging code. The package checks for the injector library and the
Java, .NET, Node.js, Python, and Ruby payload paths before building. It rewrites
the injector config's build-container path to the installed
`/opt/grafana/beyla-sdk/dist` path. `test-package.sh` can also use a synthetic
payload fixture; that verifies packaging/staging, not the SDK binaries.

In `beyla-only` mode, no application service drop-ins are created. In `sdk`
mode, `configure.py` requires an explicit unique list of existing systemd
`.service` units. For each, it writes only
`/etc/systemd/system/<unit>.d/90-grafana-beyla-sdk.conf`, with an
`EnvironmentFile` reference to `sdk.env` plus that unit's injector service
name. The environment file supplies `LD_PRELOAD` and
`OTEL_INJECTOR_CONFIG_FILE`; this is unit-scoped opt-in, not host-wide
`/etc/ld.so.preload`. It does not identify or enroll applications
automatically and does not restart application units. Operators must review
selected units and deliberately start/restart controlled workloads.

The shared Alloy config keeps the SDK OTLP receiver on loopback. In SDK mode,
the configure step disables native Beyla span export in the selected complete
config to avoid duplicate spans; only explicitly enrolled SDK services emit
traces. Beyla metrics and host profiling remain configured. This package-level
switch is why changing between modes through `dpkg-reconfigure` is unsupported.

## Lifecycle and maintenance behavior

- Initial configure checks for conflicts and validates all requested service
  targets before writing credentials, the state marker, or injection
  drop-ins. If the initial configure fails before state is recorded,
  `postinst` removes only the exact copied template config so a corrected
  installation can retry; it does not remove a changed config.
- After configuration, `postinst` validates the complete active Alloy config,
  creates or verifies its own Alloy drop-in, reloads systemd, enables
  `alloy.service`, and starts it if inactive or restarts it if already active.
  It does not restart application services.
- A subsequent configure must retain the recorded mode. A requested mode
  change fails and preserves the existing configuration. Endpoint/credential
  rotation is currently manual: edit the persistent root-only
  `/etc/grafana/beyla-sdk/alloy.env` carefully, then deliberately restart
  Alloy to apply it. Avoid putting tokens in command arguments or shell
  history.
- On `remove` or `purge`, `postrm` removes only service and Alloy drop-ins
  that still exactly match the package-generated contents. Modified drop-ins
  are preserved. It reloads systemd and, if the package had recorded an
  installation and Alloy is active, attempts to restart Alloy after removing
  its package drop-in. It never stops/removes Alloy itself or restarts
  application units.
- When no modified package drop-in has to be preserved, both `remove` and
  `purge` clear the package's `mode` and `services` state markers. `remove`
  leaves `/etc/grafana/beyla-sdk` (credentials and active config) in place;
  `purge` removes that directory too. If a modified package drop-in remains,
  the scripts preserve the state markers on either action, and `purge` also
  leaves `/etc/grafana/beyla-sdk` in place. Because a later first configure
  may reject those unmarked pre-existing config files, retention on `remove`
  does not guarantee that reinstall or reconfiguration will adopt them. These
  behaviors describe the current maintainer scripts, not a promise to manage
  operator edits beyond their exact generated files.

## Source and local checks

- `control`, `templates`, `config`: package metadata and debconf input
  declarations/prompting.
- `postinst`, `postrm`: configure and removal lifecycle.
- `configure.py`: value validation, credentials, mode selection, and SDK
  service opt-ins.
- `alloy-config.alloy`, `alloy-dropin.conf`, `validate-alloy.py`: Alloy
  configuration and validation.
- `build-deb.sh`: canonical artifact staging and DEB assembly.
- `test_configure.py`, `test-maintainer-scripts.sh`, `test-package.sh`: unit,
  mocked lifecycle, and package-staging checks.

Run the local packaging checks with:

```sh
packaging/deb/test-package.sh
```

The package is an unpublished PoC. End-to-end smoke evidence, runtime matrix
results, and release qualification claims belong with the specific change or
PR that produced them; they are not guarantees of this implementation guide.
