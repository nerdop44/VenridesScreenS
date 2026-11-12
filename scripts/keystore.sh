#!/usr/bin/env bash
# Crea (una sola vez) el keystore de firma de VScreenS fuera del repositorio.
set -euo pipefail
DEST="${VSCREENS_KEYSTORE:-$HOME/.vscreens/vscreens-release.jks}"
mkdir -p "$(dirname "$DEST")"
if [ -f "$DEST" ]; then
  echo "Ya existe: $DEST"
  exit 0
fi
: "${VSCREENS_KEYSTORE_PASSWORD:?Define VSCREENS_KEYSTORE_PASSWORD}"
keytool -genkeypair -v -keystore "$DEST" -alias "${VSCREENS_KEY_ALIAS:-vscreens}" \
  -keyalg RSA -keysize 4096 -validity 10000 \
  -storepass "$VSCREENS_KEYSTORE_PASSWORD" \
  -keypass "${VSCREENS_KEY_PASSWORD:-$VSCREENS_KEYSTORE_PASSWORD}" \
  -dname "CN=VScreenS, O=Inverpave C.A., C=VE"
chmod 600 "$DEST"
echo "Keystore creado: $DEST"
echo "Guárdalo en un lugar seguro; sin él no podrás actualizar las apps en Play Store."
