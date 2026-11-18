#!/usr/bin/env bash
set -euo pipefail

case_file=${1:?usage: extend-beyla-kafka-oats-window.sh CASE_FILE}
[[ -f "$case_file" ]] || {
  echo "OATS Kafka case not found: $case_file" >&2
  exit 1
}

matches=$(awk '
  /^input:[[:space:]]*$/ { in_input = 1; next }
  /^expected:[[:space:]]*$/ { in_input = 0 }
  in_input && $0 == "      timeout: 10s" { count++ }
  END { print count + 0 }
' "$case_file")
# OBI #4227 made upstream use the 30s window itself; accept that as a no-op.
if [[ "$matches" == 0 ]]; then
  extended=$(awk '
    /^input:[[:space:]]*$/ { in_input = 1; next }
    /^expected:[[:space:]]*$/ { in_input = 0 }
    in_input && $0 == "      timeout: 30s" { count++ }
    END { print count + 0 }
  ' "$case_file")
  [[ "$extended" == 1 ]] && exit 0
fi
[[ "$matches" == 1 ]] || {
  echo "Expected exactly one exact 10s input retry before expected: in $case_file; found $matches" >&2
  exit 1
}

tmp_file="$case_file.tmp.$$"
trap 'rm -f "$tmp_file"' EXIT
sed '/^input:[[:space:]]*$/,/^expected:[[:space:]]*$/s/^      timeout: 10s$/      timeout: 30s/' "$case_file" >"$tmp_file"
mv "$tmp_file" "$case_file"
