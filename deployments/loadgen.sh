#!/usr/bin/env bash

BASE_URL=${BASE_URL:-"https://localhost:8443"}

URLS=(
  "/"
  "/entry/about.md"
  "/entry/201709281345_md_playing.md"
  "/entry/201610281345_first.md"
  "/atom.xml"
  "/static/img.png"
  "/static/style.css"
  "/non-existing"
)
URLS_LEN=${#URLS[@]}

while true; do
  # shellcheck disable=SC2004
  URL_IDX=$((${RANDOM} % ${URLS_LEN}))
  URL="${BASE_URL}${URLS[$URL_IDX]}"
  echo "calling ${URL}"
  curl -s "${URL}"

  sleep "$(echo "scale=2;${URL_IDX} / ${URLS_LEN} " | bc)"
done
