#!/bin/bash
# Chequeo de salud de VenridesScreenS.
set -u
ok=0; fail=0
chk() { if eval "$2" >/dev/null 2>&1; then echo "OK   $1"; ok=$((ok+1)); else echo "FAIL $1"; fail=$((fail+1)); fi; }

chk "contenedor venrides-screens-odoo" "docker inspect -f '{{.State.Running}}' venrides-screens-odoo | grep -q true"
chk "contenedor venrides-screens-gateway" "docker inspect -f '{{.State.Running}}' venrides-screens-gateway | grep -q true"
chk "contenedor venrides-screens-admin" "docker inspect -f '{{.State.Running}}' venrides-screens-admin | grep -q true"
chk "contenedor venrides-screens-tv" "docker inspect -f '{{.State.Running}}' venrides-screens-tv | grep -q true"
chk "contenedor venrides-screens-landing" "docker inspect -f '{{.State.Running}}' venrides-screens-landing | grep -q true"
chk "Odoo HTTP" "docker exec venrides-screens-gateway wget -qO- http://venrides-screens-odoo:8069/web/login | grep -q -i 'odoo'"
chk "API diag" "docker exec venrides-screens-gateway wget -qO- http://venrides-screens-odoo:8069/diag/status | grep -q 'healthy'"
chk "PostgreSQL" "docker exec venrides-db pg_isready -U odoo -d venridesscreens"
chk "respaldo reciente (<36h)" "find /opt/venrides-screens/backups -name '*.dump' -mtime -2 | grep -q ."

echo "----------------------------------------"
echo "OK: $ok   FAIL: $fail"
[ "$fail" -eq 0 ]
