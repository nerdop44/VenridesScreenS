#!/bin/bash
# Bootstrap inicial de VenridesScreenS en Odoo 20 CE.
# Ejecutar como root en el VPS, desde /opt/venrides-screens.
set -euo pipefail

ROOT=/opt/venrides-screens
ENV_FILE="$ROOT/.env"
SRC="$ROOT/src"
COMPOSE="$SRC/deploy/odoo-venrides"

if [ ! -f "$ENV_FILE" ]; then
    echo "Falta $ENV_FILE. Copia .env.example y completa los secretos." >&2
    exit 1
fi

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

: "${DB_USER:?DB_USER requerido}"
: "${DB_NAME:?DB_NAME requerido}"
: "${DB_PASSWORD:?DB_PASSWORD requerido}"
: "${ODOO_ADMIN_PASSWD:?ODOO_ADMIN_PASSWD requerido}"
: "${MASTER_ADMIN_EMAIL:?MASTER_ADMIN_EMAIL requerido}"
: "${MASTER_ADMIN_PASSWORD:?MASTER_ADMIN_PASSWORD requerido}"

echo "==> Creando rol y base de datos si no existen"
docker exec -i venrides-db psql -U odoo -d postgres <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${DB_USER}') THEN
        CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASSWORD}';
    ELSE
        ALTER ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASSWORD}';
    END IF;
END
\$\$;
SQL

if ! docker exec venrides-db psql -U odoo -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1; then
    docker exec venrides-db createdb -U odoo -O "${DB_USER}" "${DB_NAME}"
fi

echo "==> Instalando el módulo venrides_screens"
cd "$COMPOSE"
docker compose --env-file "$ENV_FILE" run --rm venrides-screens-odoo \
    -d "${DB_NAME}" -i venrides_screens --without-demo=all --stop-after-init --no-http

echo "==> Levantando servicios"
docker compose --env-file "$ENV_FILE" up -d --build

echo "==> Configurando usuario maestro"
docker compose --env-file "$ENV_FILE" run --rm venrides-screens-odoo shell -d "${DB_NAME}" --no-http <<PY
import os
company = env['venrides.company'].search([('name', '=', 'Venrides Master')], limit=1)
if not company:
    company = env['venrides.company'].create({
        'name': 'Venrides Master',
        'plan_id': env.ref('venrides_screens.plan_ultra').id,
        'is_active': True,
        'max_screens': 0,
    })
user = env['res.users'].search([('login', '=', os.environ['MASTER_ADMIN_EMAIL'])], limit=1)
if not user:
    user = env['res.users'].create({
        'login': os.environ['MASTER_ADMIN_EMAIL'],
        'name': 'Administrador Maestro',
        'password': os.environ['MASTER_ADMIN_PASSWORD'],
        'venrides_role': 'admin_master',
        'venrides_company_id': company.id,
        'venrides_must_change_password': False,
    })
else:
    user.write({
        'password': os.environ['MASTER_ADMIN_PASSWORD'],
        'venrides_role': 'admin_master',
        'venrides_company_id': company.id,
        'active': True,
    })
admin = env.ref('base.user_admin', raise_if_not_found=False)
if admin:
    admin.write({'password': os.environ['ODOO_ADMIN_PASSWD']})
env.cr.commit()
print('Maestro listo:', user.login)
PY

echo "==> Instalando proxy host de NPM"
if [ -d /var/lib/docker/volumes/npm_data/_data/nginx/proxy_host ]; then
    install -m 644 "$SRC/deploy/npm/venrides-screens.conf" \
        /var/lib/docker/volumes/npm_data/_data/nginx/proxy_host/venrides-screens.conf
    docker exec npm nginx -t
    docker exec npm nginx -s reload
else
    echo "NPM no encontrado; configura los proxy hosts manualmente."
fi

echo "==> Listo. Accede a https://venrides-erp.inverpave.com"
