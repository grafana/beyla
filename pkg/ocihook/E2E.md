# Local E2E Recipe (No Real Container Start)

This recipe validates wrapper policy + mutation + spec persistence without starting a container runtime.

## 1. Build the Wrapper

```bash
go build -o ./bin/oci-runtime ./cmd/oci-runtime
```

## 2. Prepare a Minimal OCI Bundle

```bash
mkdir -p /tmp/beyla-oci-bundle
cat > /tmp/beyla-oci-bundle/config.json <<'JSON'
{
  "annotations": {
    "beyla.grafana.com/inject": "true"
  },
  "process": {
    "env": [
      "PATH=/usr/bin",
      "BEYLA_INJECT=true"
    ]
  },
  "mounts": []
}
JSON
```

## 3. Run Wrapper in Mutation Path

Use a harmless delegate (`/usr/bin/true`) so the wrapper mutates/saves the spec and exits cleanly.

```bash
BEYLA_OCI_DELEGATE_RUNTIME=/usr/bin/true \
BEYLA_OCI_SDK_PACKAGE_VERSION=v0.0.7 \
BEYLA_OCI_HOST_INSTRUMENTATION_DIR=/var/lib/beyla/instrumentation \
./bin/oci-runtime create --bundle /tmp/beyla-oci-bundle test-container
```

## 4. Verify Resulting Spec

```bash
cat /tmp/beyla-oci-bundle/config.json
```

Expected outcomes:

- Added env vars (`LD_PRELOAD`, `OTEL_INJECTOR_CONFIG_FILE`, `BEYLA_INJECTOR_SDK_PKG_VERSION`, etc.).
- Added bind mount at `/__otel_sdk_auto_instrumentation__` from `/var/lib/beyla/instrumentation/v0.0.7`.

## 5. Validate Dry-Run Mode

Reset `config.json`, then run with dry-run enabled:

```bash
BEYLA_OCI_DELEGATE_RUNTIME=/usr/bin/true \
BEYLA_OCI_SDK_PACKAGE_VERSION=v0.0.7 \
BEYLA_OCI_HOST_INSTRUMENTATION_DIR=/var/lib/beyla/instrumentation \
BEYLA_OCI_DRY_RUN=true \
./bin/oci-runtime create --bundle /tmp/beyla-oci-bundle test-container
```

Expected outcome:

- Wrapper evaluates and mutates in memory, but does not persist `config.json` changes.
