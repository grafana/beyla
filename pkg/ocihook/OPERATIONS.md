# Host Operations Guide

This guide covers installation, configuration lifecycle, upgrades, and rollback for `beyla-oci-runtime` in plain Docker hosts.

If you prefer one-shot automated setup, use the bootstrap container in `bootstrap/README.md`.

## 1. Recommended Host Layout

Use stable paths and separate binary/config/data concerns:

- Wrapper binary: `/usr/local/bin/beyla-oci-runtime`
- Instrumentation payload root: `/var/lib/beyla/instrumentation`
- Optional wrapper env file: `/etc/beyla/oci-runtime.env`
- Docker daemon drop-in: `/etc/systemd/system/docker.service.d/beyla-oci-runtime.conf`

## 2. Configure Wrapper Variables for Docker

Docker invokes the runtime wrapper as a child process. The wrapper inherits environment from the Docker daemon process.

A practical setup is to provide env vars through a Docker systemd drop-in.
The wrapper also supports direct fallback loading from `/etc/beyla/oci-runtime.env` if runtime process env propagation differs by host/runtime behavior.

### 2.1 Create env file

```bash
sudo mkdir -p /etc/beyla
sudo tee /etc/beyla/oci-runtime.env >/dev/null <<'ENV'
BEYLA_OCI_DELEGATE_RUNTIME=/usr/bin/runc
BEYLA_OCI_MODE=permissive
BEYLA_OCI_LOG_LEVEL=info
BEYLA_OCI_DECISION_REPORT=none
BEYLA_OCI_MUTATE_COMMANDS=create
BEYLA_OCI_EXISTING_LD_PRELOAD=skip
BEYLA_OCI_SDK_PACKAGE_VERSION=v0.0.9
BEYLA_OCI_HOST_INSTRUMENTATION_DIR=/var/lib/beyla/instrumentation
BEYLA_OCI_OPTIN_ANNOTATION=beyla.grafana.com/inject
BEYLA_OCI_OPTIN_ENV_VAR=BEYLA_INJECT
BEYLA_OCI_OVERRIDE_OTEL=false
BEYLA_OCI_DRY_RUN=false
ENV
```

### 2.2 Create Docker systemd drop-in

```bash
sudo mkdir -p /etc/systemd/system/docker.service.d
sudo tee /etc/systemd/system/docker.service.d/beyla-oci-runtime.conf >/dev/null <<'CONF'
[Service]
EnvironmentFile=-/etc/beyla/oci-runtime.env
CONF
```

### 2.3 Reload and restart Docker

```bash
sudo systemctl daemon-reload
sudo systemctl restart docker
```

## 3. Runtime Registration (Docker)

Register the wrapper runtime in `/etc/docker/daemon.json`:

```json
{
  "runtimes": {
    "beyla": {
      "path": "/usr/local/bin/beyla-oci-runtime",
      "runtimeArgs": []
    }
  }
}
```

Restart Docker after changes:

```bash
sudo systemctl restart docker
```

## 4. Verification Checklist

1. Binary present and executable:

```bash
ls -l /usr/local/bin/beyla-oci-runtime
```

2. Docker runtime visible:

```bash
docker info | sed -n '/Runtimes/,$p'
```

3. Wrapper smoke test (no real container start):

- Follow `E2E.md` with delegate `/usr/bin/true`.

4. Runtime usage from Docker:

```bash
docker run --runtime=beyla ...
```

## 5. Upgrade Strategy

Use an atomic symlink or replace-in-place approach:

1. Build new binary to a versioned path:

```bash
sudo install -m 0755 ./bin/oci-runtime /usr/local/bin/beyla-oci-runtime-vNEXT
```

2. Update stable symlink:

```bash
sudo ln -sfn /usr/local/bin/beyla-oci-runtime-vNEXT /usr/local/bin/beyla-oci-runtime
```

3. Restart Docker:

```bash
sudo systemctl restart docker
```

4. Run verification checklist.

## 6. Rollback Strategy

1. Point stable path back to previous binary.
2. Restore previous env values (especially SDK version or mode).
3. Restart Docker.
4. Re-run verification.

## 7. Safe Rollout Recommendations

- Start with `BEYLA_OCI_DRY_RUN=true` in one host to validate selection behavior.
- Keep `BEYLA_OCI_MODE=permissive` for initial rollout.
- Use explicit opt-in selectors (annotation/env var) to limit blast radius.
- Move to strict mode only after confidence in policy and payload availability.

## 8. Common Failure Modes

- Delegate runtime path invalid:
  - Symptom: wrapper fails before container starts.
  - Fix: verify `BEYLA_OCI_DELEGATE_RUNTIME`.

- Missing SDK payload directory:
  - Symptom: mutation may succeed but runtime startup behavior is affected later.
  - Fix: ensure `/var/lib/beyla/instrumentation/<version>` exists on host.

- Unexpected non-instrumentation:
  - Symptom: no env/mount injection.
  - Fix: verify opt-in selector matches and `create` command mutation is enabled.
