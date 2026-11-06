#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
make_bin=$(command -v make)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"

cat > "$tmp/bin/mise" <<'SH'
#!/usr/bin/env bash
printf 'start %s CMD=%s GOOS=%s\n' "$*" "${CMD-unset}" "${GOOS-unset}" >> "$EVENTS"
sleep 0.1
echo "end $*" >> "$EVENTS"
SH
cat > "$tmp/bin/go" <<'SH'
#!/usr/bin/env bash
printf 'args=%s GOOS=%s GOARCH=%s\n' "$*" "${GOOS-unset}" "${GOARCH-unset}" >> "$GO_LOG"
SH
chmod +x "$tmp/bin/"*

# These pre-bootstrap contract tests must not invoke Mise, even if it is on PATH.
if [[ "${MISE_CONTRACT_HERMETIC_CHILD:-}" != 1 ]]; then
  mkdir -p "$tmp/hostile-bin"
  cat > "$tmp/hostile-bin/mise" <<'SH'
#!/usr/bin/env bash
touch "$MISE_CONTRACT_MISE_SENTINEL"
exit 97
SH
  chmod +x "$tmp/hostile-bin/mise"
  MISE_CONTRACT_HERMETIC_CHILD=1 MISE_CONTRACT_MISE_SENTINEL="$tmp/mise-was-called" \
    PATH="$tmp/hostile-bin:$PATH" bash "${BASH_SOURCE[0]}" >"$tmp/hermetic-output"
  [[ ! -e "$tmp/mise-was-called" ]]
fi


# Each requested Make goal is forwarded separately and runs serially by default.
env -u GOOS -u GOARCH -u MAKEFLAGS -u MFLAGS -u MAKEOVERRIDES EVENTS="$tmp/events" \
  PATH="$tmp/bin:$PATH" make -C "$root" alpha beta CMD=custom >/dev/null
[[ $(cat "$tmp/events") == $'start run alpha CMD=custom GOOS=unset\nend run alpha\nstart run beta CMD=custom GOOS=unset\nend run beta' ]]

# Default target is all, command-line variables are exported, and -n is safe.
rm -f "$tmp/events"
env -u GOOS -u GOARCH -u MAKEFLAGS -u MFLAGS -u MAKEOVERRIDES EVENTS="$tmp/events" \
  PATH="$tmp/bin:$PATH" make -C "$root" CMD=default >/dev/null
grep -q '^start run all CMD=default ' "$tmp/events"
rm -f "$tmp/events"
env -u GOOS -u GOARCH -u MAKEFLAGS -u MFLAGS -u MAKEOVERRIDES EVENTS="$tmp/events" \
  PATH="$tmp/bin:$PATH" make -C "$root" -n alpha CMD=dry >"$tmp/dryrun"
[[ ! -e "$tmp/events" ]]
grep -q 'mise run alpha' "$tmp/dryrun"

# Dry-run VM and mixed goals print only; neither fake Go nor Mise executes.
env -u GOOS -u GOARCH -u MAKEFLAGS -u MFLAGS -u MAKEOVERRIDES EVENTS="$tmp/events" \
  GO_LOG="$tmp/go" PATH="$tmp/bin:$PATH" make -C "$root" -n run-integration-test-vm alpha \
  >"$tmp/vm-dryrun"
grep -q 'bash .mise/tasks/integration/run/vm' "$tmp/vm-dryrun"
grep -q 'mise run alpha' "$tmp/vm-dryrun"
[[ ! -e "$tmp/events" && ! -e "$tmp/go" ]]

# VM execution works with an isolated PATH containing bash and Go, but no Mise.
if [[ -e /precompiled-tests/integration.test ]]; then
  echo 'Cannot run VM compatibility check while /precompiled-tests/integration.test exists' >&2
  exit 1
fi
mkdir -p "$tmp/vm-bin"
ln -s "$(command -v bash)" "$tmp/vm-bin/bash"
cat > "$tmp/vm-bin/go" <<EOF
#!$tmp/vm-bin/bash
printf '%s\\n' "\$*" >> "$tmp/vm-go"
EOF
chmod +x "$tmp/vm-bin/go"
if PATH="$tmp/vm-bin" command -v mise >/dev/null 2>&1; then
  echo 'Unexpected Mise found in isolated VM PATH' >&2
  exit 1
fi
PATH="$tmp/vm-bin" "$make_bin" -C "$root" run-integration-test-vm TEST_PATTERN=VMProbe >/dev/null
grep -q VMProbe "$tmp/vm-go"


echo 'Make compatibility tests passed'
