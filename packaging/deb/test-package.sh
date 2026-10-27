#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
PACKAGE_DIR="$ROOT_DIR/packaging/deb"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s "$PACKAGE_DIR" -p 'test_*.py' -v
"$PACKAGE_DIR/test-maintainer-scripts.sh"
bash -n "$PACKAGE_DIR/build-deb.sh"
sh -n "$PACKAGE_DIR/config" "$PACKAGE_DIR/postinst" "$PACKAGE_DIR/postrm"
python3 - "$PACKAGE_DIR/configure.py" "$PACKAGE_DIR/validate-alloy.py" "$PACKAGE_DIR/test_configure.py" <<'PY'
import pathlib
import sys

for filename in sys.argv[1:]:
    source = pathlib.Path(filename).read_text(encoding="utf-8")
    compile(source, filename, "exec")
PY

# A small synthetic payload exercises DEB metadata and staging without claiming
# to validate the real image-build toolchain or SDK binaries.
fixture="$tmp/dist"
mkdir -p "$fixture/injector" "$fixture/agents/jvm" "$fixture/agents/dotnet/glibc" \
  "$fixture/agents/node.js" "$fixture/agents/python/glibc" "$fixture/agents/ruby/glibc"
cp "$ROOT_DIR/pkg/webhook/image/opentelemetry-injector/otelinject.conf" "$fixture/injector/otelinject.conf"
touch "$fixture/injector/libotelinject.so" "$fixture/agents/jvm/opentelemetry-javaagent.jar" \
  "$fixture/agents/dotnet/glibc/fixture" "$fixture/agents/node.js/register.js" \
  "$fixture/agents/python/glibc/fixture" "$fixture/agents/ruby/glibc/fixture"
OUTPUT_DIR="$tmp/out" "$PACKAGE_DIR/build-deb.sh" "$fixture"
deb="$tmp/out/grafana-beyla-sdk_0.1.0~poc1_amd64.deb"
test "$(dpkg-deb --field "$deb" Package)" = grafana-beyla-sdk
dpkg-deb --field "$deb" Depends | grep -q 'alloy'
contents=$(dpkg-deb --contents "$deb")
for path in \
  opt/grafana/beyla-sdk/dist/injector/libotelinject.so \
  opt/grafana/beyla-sdk/dist/agents/jvm/opentelemetry-javaagent.jar \
  opt/grafana/beyla-sdk/dist/agents/dotnet/glibc/fixture \
  opt/grafana/beyla-sdk/dist/agents/node.js/register.js \
  opt/grafana/beyla-sdk/dist/agents/python/glibc/fixture \
  opt/grafana/beyla-sdk/dist/agents/ruby/glibc/fixture \
  usr/share/grafana-beyla-sdk/alloy-service-dropin.conf \
  usr/share/grafana-beyla-sdk/config.alloy; do
  grep -Fq "$path" <<<"$contents"
done
dpkg-deb --extract "$deb" "$tmp/extracted"
grep -Fxq 'jvm_auto_instrumentation_agent_path=/opt/grafana/beyla-sdk/dist/agents/jvm/opentelemetry-javaagent.jar' \
  "$tmp/extracted/opt/grafana/beyla-sdk/dist/injector/otelinject.conf"
! grep -q '/__otel_sdk_auto_instrumentation__' \
  "$tmp/extracted/opt/grafana/beyla-sdk/dist/injector/otelinject.conf"
grep -q '127.0.0.1:14318' "$tmp/extracted/usr/share/grafana-beyla-sdk/config.alloy"
echo "Package fixture tests passed (SDK payload binaries were synthetic)."

# Exercise the portable engine protocol without invoking a real build. The
# Dockerfile adapter may qualify base images, but must preserve every other
# canonical Dockerfile line and must not pass Podman-private storage flags.
mock_engine="$tmp/mock-engine"
cat > "$mock_engine" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
command=$1
shift
printf '%s %s\n' "$command" "$*" >> "$ENGINE_LOG"
case "$command" in
  build)
    [[ "$1" == --platform && "$2" == linux/amd64 ]]
    while (($#)); do
      if [[ "$1" == -f ]]; then
        cp "$2" "$CAPTURED_DOCKERFILE"
        break
      fi
      shift
    done
    ;;
  create) printf 'mock-container-id\n' ;;
  cp) cp -a "$FIXTURE_DIST" "$2" ;;
  rm|rmi) ;;
  *) echo "unexpected engine command: $command" >&2; exit 1 ;;
esac
MOCK
chmod +x "$mock_engine"
engine_output="$tmp/engine-output"
mkdir -p "$engine_output"
ENGINE_LOG="$tmp/engine.log" \
CAPTURED_DOCKERFILE="$tmp/captured.Dockerfile" \
FIXTURE_DIST="$fixture" \
OUTPUT_DIR="$engine_output" \
CONTAINER_ENGINE="$mock_engine" \
  "$PACKAGE_DIR/build-deb.sh"
sed -E 's/^FROM (alpine|ruby|python|node):/FROM docker.io\/library\/\1:/' \
  "$ROOT_DIR/pkg/webhook/image/Dockerfile" > "$tmp/expected.Dockerfile"
cmp "$tmp/expected.Dockerfile" "$tmp/captured.Dockerfile"
! grep -q -- '--root\|--runroot' "$tmp/engine.log"
grep -q '^build --platform linux/amd64 --build-arg TARGETARCH=amd64 ' "$tmp/engine.log"
echo "Container-engine adapter tests passed."
