#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

VERSION_NAME="${VERSION_NAME:-0.01}"
VERSION_CODE="${VERSION_CODE:-1}"
PACKAGE="${PACKAGE:-com.marc26z.secretsecp}"
KEYSTORE="${KEYSTORE:-keystore.p12}"

if [ ! -f .keystore-password ]; then
  openssl rand -base64 24 > .keystore-password
  chmod 600 .keystore-password
fi
PASS="$(cat .keystore-password)"

if [ ! -f "$KEYSTORE" ]; then
  KEYSTORE_PASSWORD="$PASS" goapk keygen --cn "Marc26z secretSecp" "$KEYSTORE"
fi

(cd web && npm ci --silent && npm run build)

mkdir -p dist
KEYSTORE_PASSWORD="$PASS" goapk build \
  -s web/dist \
  --package "$PACKAGE" \
  --name secretSecp \
  --version-code "$VERSION_CODE" \
  --version-name "$VERSION_NAME" \
  --icon web/icon-512.png \
  --keystore "$KEYSTORE" \
  "dist/secretsecp-${VERSION_NAME}.apk"

echo "Built dist/secretsecp-${VERSION_NAME}.apk"
