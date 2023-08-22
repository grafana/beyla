#!/usr/bin/env bash

BASE_URL=${BASE_URL:-"http://localhost:3333"}

URLS=(
  "/greeting"
  "/smoke"
  "/ping?delay=300ms"
)
URLS_LEN=${#URLS[@]}

while true; do
  # shellcheck disable=SC2004
  URL_IDX=$((${RANDOM} % ${URLS_LEN}))
  URL="${BASE_URL}${URLS[$URL_IDX]}"
  echo "calling ${URL}"
  curl -k  "${URL}" > /dev/null

  sleep "$(echo "scale=4;${URL_IDX} / ${URLS_LEN}0 " | bc)"
done
