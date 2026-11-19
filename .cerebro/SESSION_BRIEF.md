# SESSION BRIEF — VScreenS

- **Proyecto:** VScreenS (Suite de Señalización Digital en Odoo 20 CE + Panel Cliente React + App TV + App Móvil Capacitor)
- **Rama activa:** `main`
- **Dominios producción:**
  - Web pública / Tienda (Odoo Website): `https://vscreens.inverpave.com`
  - Panel cliente (React): `https://vscreens-app.inverpave.com`
  - API (Odoo REST): `https://vscreens-api.inverpave.com`
  - TV App: `https://vscreens-tv.inverpave.com`
  - Odoo ERP Maestro: `https://vscreens-erp.inverpave.com`
- **Arquitectura vigente (19 nov 2026):**
  1. Todo conectado con Odoo 20 CE (`vscreens.inverpave.com` sirve Odoo Website + `/shop` + `/dl/` + `/d/CODIGO`).
  2. Control Maestro 100% en Odoo ERP; Panel Web (`frontend-admin`) y App Móvil (`app-mobile`) exclusivos para clientes.
  3. Descarga para Android TV / Fire TV con soporte nativo para **Downloader by AFTVnews** (`aftvnews_code` en `product.template` y `vscreens.download.code`) + URL directa `/d/CODIGO`.
- **Estado actual:** Fases 0–4 de remediación implementadas y verificadas localmente (43 `.py`, 34 `.xml`, 110 ACLs, `frontend-tv`, `app-tv`, `frontend-admin` y `app-mobile` compilando sin errores). Listo para commit, despliegue en VPS, configuración del código AFTVnews y build de APKs en entorno Android.
- **Reglas de oro:**
  - Nunca subir credenciales, tokens, dumps ni APKs binarios al repositorio.
  - No tocar el core de Odoo ni la base `vencafedb`.
  - Mantener `trazabilidad.md` actualizado tras cada hito.
