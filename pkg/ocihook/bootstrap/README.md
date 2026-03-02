# One-Shot Bootstrap Container (Linux)

This container configures a Linux host for `beyla-oci-runtime` in a single run.
It embeds the instrumentation payload (`/dist`) from the webhook image build as source of truth.

It performs:

1. Install runtime wrapper binary on host (`/usr/local/bin/beyla-oci-runtime` by default)
2. Write wrapper env file (`/etc/beyla/oci-runtime.env`)
3. Write Docker systemd drop-in (`/etc/systemd/system/docker.service.d/beyla-oci-runtime.conf`)
4. Merge Docker runtime config into `/etc/docker/daemon.json`
5. Optional docker restart (`RESTART_DOCKER=true`)

## Prerequisites

- Linux host running Docker Engine
- Privileged container permissions
- Host root mount available as `/host`
- Built runtime binary in repo: `bin/oci-runtime`
- Built payload image from `pkg/webhook/image/Dockerfile`

## Build Images (recommended single flow)

Use the Make target from repo root:

```bash
make oci-bootstrap-image
```

This builds:

1. `beyla-oci-payload:dev` from `pkg/webhook/image/Dockerfile` (contains `/dist`)
2. `beyla-oci-bootstrap:dev` from `pkg/ocihook/bootstrap/Dockerfile` (copies `/dist` from payload image)

If needed, manual equivalent:

```bash
make compile-oci-runtime
docker build -f pkg/webhook/image/Dockerfile -t beyla-oci-payload:dev pkg/webhook/image
docker build -f pkg/ocihook/bootstrap/Dockerfile -t beyla-oci-bootstrap:dev .
```

## Run Bootstrap (apply mode)

Minimal invocation (uses sane defaults):

```bash
docker run --rm --privileged \
  -v /:/host \
  beyla-oci-bootstrap:dev
```

Default behavior in minimal mode:

- `BEYLA_OCI_SDK_PACKAGE_VERSION=v0.0.9`
- `BEYLA_OCI_HOST_INSTRUMENTATION_DIR=/var/lib/beyla/instrumentation`
- `BEYLA_OCI_DELEGATE_RUNTIME=/usr/bin/runc`
- `BEYLA_OCI_MODE=permissive`
- `BEYLA_OCI_LOG_LEVEL=info`
- `BEYLA_OCI_DECISION_REPORT=none`
- `RESTART_DOCKER=false` (manual restart required)

Optional explicit mode (example):

```bash
docker run --rm --privileged \
  -v /:/host \
  -e BEYLA_OCI_DECISION_REPORT=stderr \
  -e RESTART_DOCKER=true \
  beyla-oci-bootstrap:dev
```

## Dry Run

Use dry-run to preview all file operations without changing host state:

```bash
docker run --rm --privileged \
  -v /:/host \
  -e BOOTSTRAP_DRY_RUN=true \
  beyla-oci-bootstrap:dev
```

## Payload Source

By default the bootstrap copies from embedded `/payload-dist` to:

`$BEYLA_OCI_HOST_INSTRUMENTATION_DIR/$BEYLA_OCI_SDK_PACKAGE_VERSION`

Override with `PAYLOAD_DIR` only if you intentionally want a different payload source.

## Notes

- By default, docker restart is not attempted (`RESTART_DOCKER=false`).
- If host restart fails, run manually on host:

```bash
sudo systemctl daemon-reload
sudo systemctl restart docker
```
