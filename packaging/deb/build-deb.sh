#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
PACKAGE_DIR="$ROOT_DIR/packaging/deb"
OUTPUT_DIR=${OUTPUT_DIR:-"$ROOT_DIR/dist"}
ARTIFACTS_DIR=${1:-}
CONTAINER_ENGINE=${CONTAINER_ENGINE:-docker}
ARCH=$(dpkg --print-architecture)
VERSION=${VERSION:-0.1.0~local1}

# Release tags are normally prefixed with "v"; Debian package versions are not.
VERSION=${VERSION#v}
# Debian treats a hyphenated suffix as a revision, which would sort a SemVer
# prerelease after its final release. Map SemVer prerelease separators to '~'.
if [[ "$VERSION" =~ ^([0-9]+(\.[0-9]+)*)(-([0-9A-Za-z][0-9A-Za-z.-]*))?(\+([0-9A-Za-z.-]+))?$ ]] &&
  [[ -n "${BASH_REMATCH[4]:-}" ]]; then
  version_base=${BASH_REMATCH[1]}
  version_prerelease=${BASH_REMATCH[4]}
  version_metadata=${BASH_REMATCH[6]:-}
  VERSION="${version_base}~${version_prerelease}"
  [[ -z "$version_metadata" ]] || VERSION+="+${version_metadata}"
fi
if [[ -z "$VERSION" ]] || ! dpkg --validate-version "$VERSION" >/dev/null 2>&1; then
  echo "Invalid Debian package version: $VERSION" >&2
  exit 1
fi
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "version=$VERSION" >> "$GITHUB_OUTPUT"
fi

if [[ "$ARCH" != amd64 ]]; then
  echo "This package currently supports Ubuntu amd64 (found $ARCH)." >&2
  exit 1
fi

tmp=$(mktemp -d)
unique_id=${tmp##*/}
image="beyla-deb-build:$unique_id"
container="beyla-deb-build-$unique_id"
BUILT_IMAGE=0
CREATED_CONTAINER=0
cleanup() {
  if [[ "$BUILT_IMAGE" = 1 ]]; then
    if [[ "$CREATED_CONTAINER" = 1 ]]; then
      "$CONTAINER_ENGINE" rm -f "$container" >/dev/null 2>&1 || true
    fi
    "$CONTAINER_ENGINE" rmi "$image" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

if [[ -z "$ARTIFACTS_DIR" ]]; then
  command -v "$CONTAINER_ENGINE" >/dev/null || {
    echo "Container engine '$CONTAINER_ENGINE' is required to build the canonical SDK artifact image" >&2
    exit 1
  }
  # Podman-based Docker-compatible CLIs may not enable unqualified image
  # searches. Qualify the existing official-library base images in a
  # temporary Containerfile, leaving the canonical recipe untouched.
  containerfile="$tmp/Dockerfile"
  sed -E 's/^FROM (alpine|ruby|python|node):/FROM docker.io\/library\/\1:/' \
    "$ROOT_DIR/pkg/webhook/image/Dockerfile" > "$containerfile"
  "$CONTAINER_ENGINE" build --platform linux/amd64 --build-arg TARGETARCH=amd64 --tag "$image" \
    -f "$containerfile" "$ROOT_DIR/pkg/webhook/image"
  BUILT_IMAGE=1
  "$CONTAINER_ENGINE" create --name "$container" "$image" >/dev/null
  CREATED_CONTAINER=1
  "$CONTAINER_ENGINE" cp "$container:/dist" "$tmp/dist"
  ARTIFACTS_DIR="$tmp/dist"
fi

for artifact in \
  injector/libotelinject.so \
  agents/jvm/opentelemetry-javaagent.jar \
  agents/dotnet/glibc \
  agents/node.js/register.js \
  agents/python/glibc \
  agents/ruby/glibc; do
  [[ -e "$ARTIFACTS_DIR/$artifact" ]] || { echo "Missing canonical SDK artifact: $artifact" >&2; exit 1; }
done

stage="$tmp/package"
install -d "$stage/DEBIAN" "$stage/opt/beyla/sdk/dist" \
  "$stage/usr/share/beyla" "$stage/usr/lib/beyla"
cp -a "$ARTIFACTS_DIR/." "$stage/opt/beyla/sdk/dist/"
sed 's|/__otel_sdk_auto_instrumentation__/dist|/opt/beyla/sdk/dist|g' \
  "$stage/opt/beyla/sdk/dist/injector/otelinject.conf" \
  > "$stage/opt/beyla/sdk/dist/injector/otelinject.conf.tmp"
mv "$stage/opt/beyla/sdk/dist/injector/otelinject.conf.tmp" \
  "$stage/opt/beyla/sdk/dist/injector/otelinject.conf"
install -m 0644 "$PACKAGE_DIR/alloy-config.alloy" "$stage/usr/share/beyla/config.alloy"
install -m 0644 "$PACKAGE_DIR/alloy-dropin.conf" \
  "$stage/usr/share/beyla/alloy-service-dropin.conf"
install -m 0644 "$PACKAGE_DIR/configure.py" "$stage/usr/lib/beyla/configure.py"
install -m 0644 "$PACKAGE_DIR/validate-alloy.py" "$stage/usr/lib/beyla/validate-alloy.py"
install -m 0644 "$PACKAGE_DIR/templates" "$stage/DEBIAN/templates"
sed "s/^Version: .*/Version: $VERSION/" "$PACKAGE_DIR/control" > "$stage/DEBIAN/control"
install -m 0755 "$PACKAGE_DIR/config" "$stage/DEBIAN/config"
install -m 0755 "$PACKAGE_DIR/preinst" "$stage/DEBIAN/preinst"
install -m 0755 "$PACKAGE_DIR/postinst" "$stage/DEBIAN/postinst"
install -m 0755 "$PACKAGE_DIR/postrm" "$stage/DEBIAN/postrm"

install -d "$OUTPUT_DIR"
dpkg-deb --build --root-owner-group "$stage" \
  "$OUTPUT_DIR/beyla_${VERSION}_amd64.deb"
echo "Built Beyla package: $OUTPUT_DIR/beyla_${VERSION}_amd64.deb"
