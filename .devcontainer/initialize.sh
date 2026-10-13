#!/bin/sh
set -eu

# Initialize a fresh clone without moving an existing OBI development checkout.
if [ ! -f .obi-src/generator.Dockerfile ]; then
    git submodule update --init --recursive -- .obi-src
fi
