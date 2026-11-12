#!/usr/bin/env bash
# Construye y firma los APK de VScreenS (móvil y TV).
# Requisitos: Node 20+, JDK 17+ (probado con JDK 21), Android SDK
# (platform 34, build-tools 34.0.0).
#
# Firma: define VSCREENS_KEYSTORE y VSCREENS_KEYSTORE_PASSWORD
# (ver scripts/keystore.sh). En el VPS se leen de /opt/vscreens/.env.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Credenciales y rutas del VPS (si existen).
if [ -f /opt/vscreens/.env ]; then
    set -a
    # shellcheck disable=SC1091
    . /opt/vscreens/.env
    set +a
fi

if [ -x /usr/lib/jvm/java-21-openjdk-amd64/bin/java ]; then
    export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"
elif [ -x /usr/lib/jvm/java-17-openjdk-amd64/bin/java ]; then
    export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}"
fi
[ -n "${JAVA_HOME:-}" ] && export PATH="$JAVA_HOME/bin:$PATH"

if [ -d /opt/android-sdk ]; then
    : "${ANDROID_SDK_ROOT:=/opt/android-sdk}"
fi
: "${ANDROID_SDK_ROOT:=${ANDROID_HOME:-$HOME/Android/Sdk}}"
export ANDROID_SDK_ROOT ANDROID_HOME="$ANDROID_SDK_ROOT"
export PATH="$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$PATH"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-/opt/gradle-home}"

: "${VSCREENS_KEYSTORE:=/opt/vscreens/keystores/vscreens-release.jks}"
: "${VSCREENS_KEY_ALIAS:=vscreens}"
export VSCREENS_KEYSTORE VSCREENS_KEY_ALIAS
if [ ! -f "$VSCREENS_KEYSTORE" ]; then
    echo "Falta el keystore $VSCREENS_KEYSTORE. Ejecuta scripts/keystore.sh." >&2
    exit 1
fi
if [ -z "${VSCREENS_KEYSTORE_PASSWORD:-}" ]; then
    echo "Falta VSCREENS_KEYSTORE_PASSWORD." >&2
    exit 1
fi

echo "==> APK móvil (panel cliente/master)"
cd "$ROOT/app-mobile"
npm ci --no-audit --no-fund
VITE_API_BASE_URL="${VITE_API_BASE_URL:-https://vscreens-api.inverpave.com}" npm run build
npx cap sync android
cd android
./gradlew assembleRelease --no-daemon

echo "==> APK TV"
cd "$ROOT/app-tv"
npm ci --no-audit --no-fund
npm run build
npx cap sync android
cd android
./gradlew assembleRelease --no-daemon

echo "==> Publicando APK"
RELEASES="$ROOT/releases"
mkdir -p "$RELEASES"
cp "$ROOT/app-mobile/android/app/build/outputs/apk/release/app-release.apk" "$RELEASES/VScreenS_Mobile.apk"
cp "$ROOT/app-tv/android/app/build/outputs/apk/release/app-release.apk" "$RELEASES/VScreenS_TV.apk"
chmod 644 "$RELEASES"/*.apk

echo "==> Resultados"
ls -lh "$RELEASES/VScreenS_Mobile.apk" "$RELEASES/VScreenS_TV.apk"
sha256sum "$RELEASES/VScreenS_Mobile.apk" "$RELEASES/VScreenS_TV.apk"
