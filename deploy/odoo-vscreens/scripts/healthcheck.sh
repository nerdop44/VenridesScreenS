#!/bin/bash
# Chequeo de salud de VScreenS.
set -u
ok=0; fail=0
chk() { if eval "$2" >/dev/null 2>&1; then echo "OK   $1"; ok=$((ok+1)); else echo "FAIL $1"; fail=$((fail+1)); fi; }

chk "contenedor vscreens-odoo" "docker inspect -f '{{.State.Running}}' vscreens-odoo | grep -q true"
chk "contenedor vscreens-gateway" "docker inspect -f '{{.State.Running}}' vscreens-gateway | grep -q true"
chk "contenedor vscreens-admin" "docker inspect -f '{{.State.Running}}' vscreens-admin | grep -q true"
chk "contenedor vscreens-tv" "docker inspect -f '{{.State.Running}}' vscreens-tv | grep -q true"
chk "contenedor vscreens-landing" "docker inspect -f '{{.State.Running}}' vscreens-landing | grep -q true"
chk "Odoo HTTP" "docker exec vscreens-gateway wget -qO- http://vscreens-odoo:8069/web/login | grep -q -i 'odoo'"
chk "API diag" "docker exec vscreens-gateway wget -qO- http://vscreens-odoo:8069/diag/status | grep -q 'healthy'"
chk "PostgreSQL" "docker exec vscreens-db pg_isready -U vscreens -d vscreens"
chk "respaldo reciente (<36h)" "find /opt/vscreens/backups -name '*.dump' -mtime -2 | grep -q ."

echo "----------------------------------------"
echo "OK: $ok   FAIL: $fail"
if [ "$fail" -eq 0 ]; then
    docker exec vscreens-uptime wget -qO- \
        "http://127.0.0.1:3001/api/push/vscreensHC2026token02?status=up&msg=OK" \
        >/dev/null 2>&1 || true
else
    docker exec vscreens-uptime wget -qO- \
        "http://127.0.0.1:3001/api/push/vscreensHC2026token02?status=down&msg=${fail}%20fallos" \
        >/dev/null 2>&1 || true
fi
[ "$fail" -eq 0 ]
