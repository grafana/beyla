# OCI Hook Docker Compose Demo

Bring up the demo stack:

```bash
docker compose up -d --force-recreate
```

Run validation checks (host + container assertions):

```bash
./validate.sh
```

The validator confirms:

1. Docker runtime `beyla` is registered.
2. Host payload exists at `${BEYLA_OCI_HOST_INSTRUMENTATION_DIR}/${BEYLA_OCI_SDK_PACKAGE_VERSION}`.
3. Injected container contains runtime-injected env vars and mounted injector library.
4. Baseline container does not contain injected runtime env vars.

Tail collector logs:

```bash
docker compose logs -f otel-collector
```

Tail wrapper decisions from Docker service logs:

```bash
sudo journalctl -u docker.service -f | grep -E 'ocihook.wrapper|policyMatched|mutationReason|finalStatus'
```
