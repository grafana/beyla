#!/usr/bin/env bash

BASE_URL=${BASE_URL:-"https://localhost:8443"}

URLS=(
  "/" "/" "/" "/" "/" "/" "/"
  "/entry/about.md" "/entry/about.md" "/entry/about.md" "/entry/about.md" "/entry/about.md" "/entry/about.md"
  "/entry/201709281345_md_playing.md"
  "/entry/201709281345_md_playing.md"
  "/entry/201709281345_md_playing.md"
  "/entry/201709281345_md_playing.md"
  "/entry/201709281345_md_playing.md"
  "/entry/201610281345_first.md"
  "/entry/201610281345_first.md"
  "/entry/201610281345_first.md"
  "/entry/201610281345_first.md"
  "/atom.xml"
  "/atom.xml"
  "/atom.xml"
  "/static/img.png"
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
  curl -k  "${URL}" > /dev/null

  sleep "$(echo "scale=4;${URL_IDX} / ${URLS_LEN}0 " | bc)"
done
