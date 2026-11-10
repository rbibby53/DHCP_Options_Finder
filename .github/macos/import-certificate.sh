#!/usr/bin/env bash
# Import the Developer ID Application certificate into a throwaway keychain and export
# MACOS_SIGN_IDENTITY for later steps. Needs MACOS_CERT_P12 (base64) and MACOS_CERT_PASSWORD.
set -euo pipefail
keychain="$RUNNER_TEMP/signing.keychain-db"
kc_pass="$(uuidgen)"
security create-keychain -p "$kc_pass" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security unlock-keychain -p "$kc_pass" "$keychain"
printf '%s' "$MACOS_CERT_P12" | base64 --decode > "$RUNNER_TEMP/cert.p12"
security import "$RUNNER_TEMP/cert.p12" -k "$keychain" -P "$MACOS_CERT_PASSWORD" -T /usr/bin/codesign
rm -f "$RUNNER_TEMP/cert.p12"
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$kc_pass" "$keychain" >/dev/null
# Put it on the search list so codesign can find it.
existing=()
while IFS= read -r k; do
  k="${k//\"/}"; k="${k#"${k%%[![:space:]]*}"}"
  [ -n "$k" ] && existing+=("$k")
done < <(security list-keychains -d user)
security list-keychains -d user -s "$keychain" "${existing[@]}"
identity=$(security find-identity -v -p codesigning "$keychain" \
  | awk -F'"' '/Developer ID Application/ {print $2; exit}')
if [ -z "$identity" ]; then
  echo "::error::MACOS_CERT_P12 has no 'Developer ID Application' certificate with its private key."
  security find-identity -v -p codesigning "$keychain" || true
  exit 1
fi
echo "Signing identity: $identity"
echo "MACOS_SIGN_IDENTITY=$identity" >> "$GITHUB_ENV"
echo "MACOS_KEYCHAIN=$keychain" >> "$GITHUB_ENV"
