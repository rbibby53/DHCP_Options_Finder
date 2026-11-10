#!/usr/bin/env bash
# Submit a zip to Apple's notary service and wait. Prints Apple's log on rejection.
# Usage: notarize.sh FILE.zip   Needs APPLE_API_KEY_P8, APPLE_API_KEY_ID, APPLE_API_ISSUER_ID.
set -euo pipefail
zip="$1"
key="$RUNNER_TEMP/AuthKey.p8"
printf '%s\n' "$APPLE_API_KEY_P8" > "$key"
auth=(--key "$key" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER_ID")
out=$(xcrun notarytool submit "$zip" "${auth[@]}" --wait --timeout 30m --output-format json)
echo "$out"
id=$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
status=$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')
if [ "$status" != "Accepted" ]; then
  echo "::error::Notarization of $(basename "$zip") returned '$status'. Apple's log:"
  xcrun notarytool log "$id" "${auth[@]}" || true
  rm -f "$key"
  exit 1
fi
rm -f "$key"
echo "Notarized $(basename "$zip") (submission $id)."
