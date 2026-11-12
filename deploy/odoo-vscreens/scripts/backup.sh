#!/bin/bash
# Respaldo de la base de datos y del filestore de VScreenS.
set -euo pipefail

ROOT=/opt/vscreens
ENV_FILE="$ROOT/.env"
DEST="$ROOT/backups"
STAMP=$(date +%Y%m%d-%H%M%S)
DAYS=14

[ -f "$ENV_FILE" ] || { echo "Falta $ENV_FILE" >&2; exit 1; }
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

mkdir -p "$DEST"

echo "[$(date -Is)] Iniciando respaldo $STAMP"
docker exec -e PGPASSWORD="$DB_PASSWORD" vscreens-db \
    pg_dump -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -Fc \
    -f "/tmp/${DB_NAME}-${STAMP}.dump"
docker cp "vscreens-db:/tmp/${DB_NAME}-${STAMP}.dump" "$DEST/${DB_NAME}-${STAMP}.dump"
docker exec vscreens-db rm -f "/tmp/${DB_NAME}-${STAMP}.dump"

docker run --rm -v vscreens_odoo_data:/data:ro -v "$DEST":/backup alpine \
    tar czf "/backup/filestore-${STAMP}.tar.gz" -C /data filestore 2>/dev/null || true

find "$DEST" -type f -name '*.dump' -mtime +$DAYS -delete
find "$DEST" -type f -name 'filestore-*.tar.gz' -mtime +$DAYS -delete

echo "[$(date -Is)] Respaldo OK: $STAMP"
ls -lh "$DEST" | tail -4
