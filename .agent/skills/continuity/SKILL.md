---
name: continuity
description: Instrucciones para retomar el hilo de trabajo de VenridesScreenS sin exponer credenciales.
---

# Skill de Continuidad - VenridesScreenS

## Contexto

- El proyecto migra su backend y dashboard maestro a **Odoo 20 CE**.
- El dashboard del cliente, la app de TV y la landing se conservan.
- Dominios de producción:
  - Landing: `https://venrides.inverpave.com`
  - Panel cliente: `https://venrides-app.inverpave.com`
  - API: `https://venrides-api.inverpave.com`
  - TV: `https://venrides-tv.inverpave.com`
  - Odoo maestro: `https://venrides-erp.inverpave.com`
- El plan completo está en `PLAN_MIGRACION_ODOO.md` (documento interno, ignorado por Git).

## Pasos de activación

1. Leer `PLAN_MIGRACION_ODOO.md` y el estado actual del repositorio.
2. Revisar `git status`, `git log -5` y la rama activa.
3. Verificar el estado del VPS con la llave SSH configurada (sin contraseñas).
4. Revisar los logs recientes de Odoo y del gateway.

## Reglas de oro

- **Nunca** escribir credenciales, tokens, llaves privadas ni IPs internas en el repositorio.
- Los secretos viven en `/opt/venrides-screens/.env` o en el gestor de secretos.
- No tocar la base `vencafedb` ni el Odoo del café.
- Mantener la compatibilidad de la API para el dashboard del cliente y la TV.
- Versionar assets de TV (`?v=...`) para forzar actualización en Smart TVs.
- Los planes y límites se configuran en Odoo, no hardcodeados en el frontend.
- Antes de cambiar DNS, probar en staging y verificar backups.
