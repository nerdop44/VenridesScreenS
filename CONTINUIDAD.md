# CONTINUIDAD DEL PROYECTO: VScreenS

Para retomar el hilo de este proyecto, lee primero en este orden:

1. **Brief de Sesión:** `.cerebro/SESSION_BRIEF.md`
2. **Trazabilidad Viva:** `trazabilidad.md`
3. **Skill de Sistema:** `.agent/skills/continuity/SKILL.md`

## Estado Actual (2026-11-19)
- Backend y Control Maestro 100% en **Odoo 20 CE** (`odoo-addons/vscreens/`).
- `vscreens.inverpave.com` conectado a **Odoo Website + eCommerce (`/shop`) + `/d/CODIGO`**.
- Panel Cliente (`frontend-admin`) y App Móvil (`app-mobile`) exclusivos para clientes, compilando sin errores.
- App TV (`frontend-tv` / `app-tv`) endurecida para operación 24/7 (caché offline, D-Pad, `BootReceiver`, `FLAG_KEEP_SCREEN_ON`, sin congelamiento de playlist).
- Descargas TV compatibles con **Downloader by AFTVnews** (`aftvnews_code` configurable/generable desde Odoo).
