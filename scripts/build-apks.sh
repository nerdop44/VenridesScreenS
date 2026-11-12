#!/usr/bin/env bash
# Construye los APK de VScreenS (móvil y TV).
# Requisitos: Node 20+, JDK 17, Android SDK (platform 34, build-tools 34.0.0).
# Firma: define VSCREENS_KEYSTORE / VSCREENS_KEYSTORE_PASSWORD (ver scripts/keystore.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

: "${ANDROID_SDK_ROOT:=${ANDROID_HOME:-$HOME/Android/Sdk}}"
export ANDROID_SDK_ROOT ANDROID_HOME="$ANDROID_SDK_ROOT"
export PATH="$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$PATH"

echo "==> APK móvil (panel cliente/master)"
cd "$ROOT/app-mobile"
npm ci
VITE_API_BASE_URL="${VITE_API_BASE_URL:-https://vscreens-api.inverpave.com}" npm run build
npx cap sync android
cd android
./gradlew assembleRelease

echo "==> APK TV"
cd "$ROOT/app-tv"
npm ci
npm run build
npx cap sync android
cd android
./gradlew assembleRelease

echo "==> Resultados"
find "$ROOT/app-mobile/android/app/build/outputs/apk/release" "$ROOT/app-tv/android/app/build/outputs/apk/release" \
  -name '*.apk' -print -exec ls -lh {} \;
