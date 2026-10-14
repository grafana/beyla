#!/bin/sh

COV=`echo "$1" | sed 's/[.].*//'`

if [ "$COV" -lt "50" ]; then
    COLOR="#c00000"
elif [ "$COV" -lt "80" ]; then
    COLOR="#c08000"
else
    COLOR="#00c000"
fi

sed -e "s/999/$1/" -e "s/#888888/$COLOR/" assets/coverage-badge-template.svg > assets/coverage-badge.svg
