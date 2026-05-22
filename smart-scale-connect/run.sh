#!/bin/sh
set -e

cd /config

SLEEP="24h"

if [ -f "/data/options.json" ]; then
  OPT_SLEEP="$(jq --raw-output '.sleep // empty' /data/options.json)"
  if [ -n "$OPT_SLEEP" ] && [ "$OPT_SLEEP" != "null" ]; then
    SLEEP="$OPT_SLEEP"
  fi

  OPT_CONFIG="$(jq --raw-output '.scaleconnect_yaml // empty' /data/options.json)"
  if [ -n "$OPT_CONFIG" ] && [ "$OPT_CONFIG" != "null" ]; then
    printf "%s\n" "$OPT_CONFIG" > /config/scaleconnect.yaml
  fi
fi

if [ ! -f "/config/scaleconnect.yaml" ]; then
  echo "ERROR: /config/scaleconnect.yaml not found"
  echo "Paste your SmartScaleConnect YAML into the add-on option: scaleconnect_yaml"
  echo "Or create scaleconnect.yaml manually in the add-on config directory."
  exit 1
fi

if ! grep -q "from:" /config/scaleconnect.yaml; then
  echo "ERROR: /config/scaleconnect.yaml looks empty or contains only the sample comments."
  echo "Open the add-on Configuration tab and paste your real SmartScaleConnect config into scaleconnect_yaml."
  exit 1
fi

echo "Using /config/scaleconnect.yaml"
exec scaleconnect -i -r "$SLEEP"
