#!/usr/bin/env sh

run_testserver()
{
  # prefix for start ports. E.g. 808
  sp=$1
  STD_PORT=${1}0 GIN_PORT=${1}1 GORILLA_PORT=${1}2 GORILLA_MID_PORT=${1}3 GORILLA_MID2_PORT=${1}7 ./duped_service -port ${1}4
}

# runs testserver twice
run_testserver 1808 &
run_testserver 1809
