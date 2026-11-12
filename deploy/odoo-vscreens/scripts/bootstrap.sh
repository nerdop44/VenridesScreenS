#!/bin/bash
# Bootstrap inicial de VScreenS en Odoo 20 CE.
# Ejecutar como root en el VPS, desde /opt/vscreens.
set -euo pipefail

ROOT=/opt/vscreens
ENV_FILE="$ROOT/.env"
SRC="$ROOT/src"
COMPOSE="$SRC/deploy/odoo-vscreens"

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

echo "==> Red y base de datos"
docker network inspect vscreens-net >/dev/null 2>&1 || docker network create vscreens-net
cd "$COMPOSE"
docker compose --env-file "$ENV_FILE" up -d vscreens-db
for i in $(seq 1 30); do
    if docker exec vscreens-db pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then break; fi
    sleep 2
done
docker exec vscreens-db pg_isready -U "$DB_USER" -d "$DB_NAME"

echo "==> Instalando el módulo vscreens"
docker compose --env-file "$ENV_FILE" run --rm vscreens-odoo \
    -d "${DB_NAME}" -i vscreens --without-demo=all --stop-after-init --no-http

echo "==> Levantando servicios"
docker compose --env-file "$ENV_FILE" up -d --build

echo "==> Conectando NPM a la red de VScreenS"
docker network connect vscreens-net npm >/dev/null 2>&1 || true

echo "==> Configurando usuario maestro, admin y correo"
docker compose --env-file "$ENV_FILE" run --rm vscreens-odoo shell -d "${DB_NAME}" --no-http <<PY
import os
company = env['vscreens.company'].search([('name', '=', 'VScreenS Master')], limit=1)
if not company:
    company = env['vscreens.company'].create({
        'name': 'VScreenS Master',
        'plan_id': env.ref('vscreens.plan_ultra').id,
        'is_active': True,
        'max_screens': 0,
    })
user = env['res.users'].search([('login', '=', os.environ['MASTER_ADMIN_EMAIL'])], limit=1)
if not user:
    user = env['res.users'].create({
        'login': os.environ['MASTER_ADMIN_EMAIL'],
        'name': 'Administrador Maestro',
        'password': os.environ['MASTER_ADMIN_PASSWORD'],
        'vscreens_role': 'admin_master',
        'vscreens_company_id': company.id,
        'vscreens_must_change_password': False,
    })
else:
    user.write({
        'password': os.environ['MASTER_ADMIN_PASSWORD'],
        'vscreens_role': 'admin_master',
        'vscreens_company_id': company.id,
        'active': True,
    })
admin = env.ref('base.user_admin', raise_if_not_found=False)
if admin and os.environ.get('ODOO_ADMIN_USER_PASSWORD'):
    admin.write({'password': os.environ['ODOO_ADMIN_USER_PASSWORD']})
server = env['ir.mail_server'].search([('name', '=', 'VScreens SMTP')], limit=1)
mail_vals = {
    'name': 'VScreens SMTP',
    'smtp_host': os.environ.get('MAIL_HOST', 'smtp.inverpave.com'),
    'smtp_port': int(os.environ.get('MAIL_PORT', '587')),
    'smtp_user': os.environ.get('MAIL_USER', 'info.vscreens@inverpave.com'),
    'smtp_pass': os.environ.get('MAIL_PASSWORD', ''),
    'smtp_authentication': 'login',
    'smtp_encryption': 'starttls',
    'from_filter': os.environ.get('MAIL_USER', 'info.vscreens@inverpave.com'),
    'sequence': 1,
}
if server:
    server.write(mail_vals)
else:
    env['ir.mail_server'].create(mail_vals)
env['ir.config_parameter'].sudo().set_str('mail.default.from', os.environ.get('MAIL_USER', 'info.vscreens@inverpave.com'))
env['ir.config_parameter'].sudo().set_str('vscreens.notification_email', os.environ.get('MAIL_USER', 'info.vscreens@inverpave.com'))
env.cr.commit()
print('Maestro listo:', user.login)
print('Admin password configurado')
print('SMTP configurado:', mail_vals['smtp_host'], mail_vals['smtp_user'])
PY

echo "==> Instalando proxy host de NPM"
if [ -d /var/lib/docker/volumes/npm_data/_data/nginx/proxy_host ]; then
    install -m 644 "$SRC/deploy/npm/vscreens.conf" \
        /var/lib/docker/volumes/npm_data/_data/nginx/proxy_host/vscreens.conf
    docker exec npm nginx -t
    docker exec npm nginx -s reload
else
    echo "NPM no encontrado; configura los proxy hosts manualmente."
fi

echo "==> Listo. Accede a https://vscreens-erp.inverpave.com"
