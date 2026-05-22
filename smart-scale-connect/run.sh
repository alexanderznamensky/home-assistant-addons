#!/bin/sh
set -e

SLEEP="6h"
CONFIG="/homeassistant/scaleconnect.yaml"
FALLBACK_CONFIG="/config/scaleconnect.yaml"

if [ -f "/data/options.json" ]; then
  OPT_SLEEP="$(jq --raw-output '.sleep // empty' /data/options.json)"
  if [ -n "$OPT_SLEEP" ] && [ "$OPT_SLEEP" != "null" ]; then
    SLEEP="$OPT_SLEEP"
  fi
fi

if [ -f "$CONFIG" ]; then
  echo "Using $CONFIG"
  cd /homeassistant
  exec scaleconnect -c "$CONFIG" -i -r "$SLEEP"
fi

if [ -f "$FALLBACK_CONFIG" ]; then
  echo "Using fallback $FALLBACK_CONFIG"
  cd /config
  exec scaleconnect -c "$FALLBACK_CONFIG" -i -r "$SLEEP"
fi

echo "ERROR: scaleconnect.yaml not found"
echo "Expected config file: $CONFIG"
echo "Fallback config file: $FALLBACK_CONFIG"
echo "Create /homeassistant/scaleconnect.yaml in Home Assistant config directory."
exit 1
