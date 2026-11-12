---
description: despliegue de VScreenS en el VPS de producción
---

# Despliegue de VScreenS

> Este repositorio es público. **Nunca** escribas contraseñas, tokens, llaves privadas ni IPs internas en este archivo.

## Requisitos

- Llave SSH configurada para el usuario de despliegue (sin contraseña).
- Acceso al directorio `/opt/vscreens` del VPS.
- Variables de entorno en `/opt/vscreens/.env` (permisos `600`, fuera de Git).
- Docker y Docker Compose instalados.

## Flujo

1. Subir cambios al repositorio:
   ```bash
   git add .
   git commit -m "update: deploy"
   git push origin main
   ```

2. Desplegar en el VPS:
   ```bash
   ssh vscreens-prod "cd /opt/vscreens && ./scripts/deploy.sh"
   ```

3. Verificar servicios:
   ```bash
   ssh vscreens-prod "cd /opt/vscreens && docker compose ps"
   ```

4. Verificar salud:
   ```bash
   curl -fsS https://vscreens-api.inverpave.com/diag/status
   ```

## Reglas

- No usar `sshpass`, contraseñas en texto plano ni `StrictHostKeyChecking=no`.
- No subir `.env`, dumps, backups, APKs ni credenciales al repositorio.
- Los secretos se gestionan en `/opt/vscreens/.env` y en el gestor de secretos del equipo.
