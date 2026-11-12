#!/bin/bash
# Despliegue rutinario de VScreenS.
set -euo pipefail

ROOT=/opt/vscreens
ENV_FILE="$ROOT/.env"
SRC="$ROOT/src"
COMPOSE="$SRC/deploy/odoo-vscreens"

[ -f "$ENV_FILE" ] || { echo "Falta $ENV_FILE" >&2; exit 1; }
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

echo "==> Actualizando código"
git -C "$SRC" pull --ff-only

cd "$COMPOSE"
echo "==> Actualizando imágenes y contenedores"
docker compose --env-file "$ENV_FILE" build
docker compose --env-file "$ENV_FILE" up -d

echo "==> Actualizando módulo Odoo"
docker compose --env-file "$ENV_FILE" stop vscreens-odoo
UPGRADE_STATUS=0
docker compose --env-file "$ENV_FILE" run --rm vscreens-odoo \
    -d "${DB_NAME}" -u vscreens --stop-after-init --no-http || UPGRADE_STATUS=$?
docker compose --env-file "$ENV_FILE" up -d vscreens-odoo vscreens-gateway
if [ "$UPGRADE_STATUS" -ne 0 ]; then
    echo "La actualización del módulo falló (código $UPGRADE_STATUS). Odoo se reinició con la versión anterior." >&2
    exit "$UPGRADE_STATUS"
fi

echo "==> Conectando NPM a la red de VScreenS"
docker network connect vscreens-net npm >/dev/null 2>&1 || true

echo "==> Recargando NPM (si existe)"
if [ -d /var/lib/docker/volumes/npm_data/_data/nginx/proxy_host ]; then
    install -m 644 "$SRC/deploy/npm/vscreens.conf" \
        /var/lib/docker/volumes/npm_data/_data/nginx/proxy_host/vscreens.conf
    docker exec npm nginx -t && docker exec npm nginx -s reload
fi

echo "==> Despliegue completado"
