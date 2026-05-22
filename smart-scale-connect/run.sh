#!/bin/sh
set -e

cd /config

SLEEP="24h"

if [ -f "/data/options.json" ]; then
  OPT_SLEEP="$(jq --raw-output '.sleep // empty' /data/options.json)"
  if [ -n "$OPT_SLEEP" ] && [ "$OPT_SLEEP" != "null" ]; then
    SLEEP="$OPT_SLEEP"
  fi
fi

if [ ! -f "/config/scaleconnect.yaml" ]; then
  echo "ERROR: /config/scaleconnect.yaml not found"
  echo "Create scaleconnect.yaml in the add-on configuration directory."
  exit 1
fi

exec scaleconnect -i -r "$SLEEP"
