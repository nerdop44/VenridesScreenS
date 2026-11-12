#!/bin/bash
# Despliegue rutinario de VenridesScreenS.
set -euo pipefail

ROOT=/opt/venrides-screens
ENV_FILE="$ROOT/.env"
SRC="$ROOT/src"
COMPOSE="$SRC/deploy/odoo-venrides"

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
docker compose --env-file "$ENV_FILE" stop venrides-screens-odoo
UPGRADE_STATUS=0
docker compose --env-file "$ENV_FILE" run --rm venrides-screens-odoo \
    -d "${DB_NAME}" -u venrides_screens --stop-after-init --no-http || UPGRADE_STATUS=$?
docker compose --env-file "$ENV_FILE" up -d venrides-screens-odoo venrides-screens-gateway
if [ "$UPGRADE_STATUS" -ne 0 ]; then
    echo "La actualización del módulo falló (código $UPGRADE_STATUS). Odoo se reinició con la versión anterior." >&2
    exit "$UPGRADE_STATUS"
fi

echo "==> Recargando NPM (si existe)"
if [ -d /var/lib/docker/volumes/npm_data/_data/nginx/proxy_host ]; then
    install -m 644 "$SRC/deploy/npm/venrides-screens.conf" \
        /var/lib/docker/volumes/npm_data/_data/nginx/proxy_host/venrides-screens.conf
    docker exec npm nginx -t && docker exec npm nginx -s reload
fi

echo "==> Despliegue completado"
