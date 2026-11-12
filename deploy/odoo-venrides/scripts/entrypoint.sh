#!/bin/sh
set -eu

CONF=/tmp/odoo.conf

cat > "$CONF" <<EOF
[options]
admin_passwd = ${ODOO_ADMIN_PASSWD:?ODOO_ADMIN_PASSWD is required}
db_host = ${DB_HOST:-venrides-db}
db_port = ${DB_PORT:-5432}
db_user = ${DB_USER:-vscreens}
db_password = ${DB_PASSWORD:?DB_PASSWORD is required}
db_name = ${DB_NAME:-venridesscreens}
dbfilter = ^${DB_NAME:-venridesscreens}$
addons_path = /mnt/extra-addons,/usr/lib/python3/dist-packages/odoo/addons
data_dir = /var/lib/odoo
proxy_mode = True
http_interface = 0.0.0.0
list_db = False
workers = ${ODOO_WORKERS:-2}
max_cron_threads = 1
limit_time_real = 600
limit_time_cpu = 600
log_level = ${ODOO_LOG_LEVEL:-info}
EOF

exec odoo --config="$CONF" "$@"
