# Trazabilidad del Proyecto — VScreenS

## 2026-11-19 — Remediación Integral Post-Auditoría (Fases 0–4 Completadas en Código)

### Decisiones del Producto (Confirmadas por el Usuario)
1. **Todo conectado con Odoo:** `vscreens.inverpave.com` sirve Odoo Website + `/shop` + `/dl/` + `/d/CODIGO` (case-insensitive). Se retira `vscreens-landing` del stack de producción.
2. **Separación de roles:** Control Maestro 100% en Odoo ERP (`vscreens-erp.inverpave.com/odoo`); Panel Web (`frontend-admin`) y App Móvil (`app-mobile`) exclusivos y optimizados para el cliente final.
3. **Downloader by AFTVnews:** Soporte nativo para códigos numéricos de `aftvnews.com` (`go.aftvnews.com`) en `product.template`, `vscreens.download.code` y correos de entrega/bienvenida, manteniendo la URL directa `https://vscreens.inverpave.com/d/CODIGO` como respaldo.
4. **Seguridad (Fase 0):** Cierre de vulnerabilidades P0 y redacción de secretos en el repositorio.

### Registro de Ejecución Completado
- [x] **Trazabilidad:** Creados `.cerebro/SESSION_BRIEF.md` y `trazabilidad.md`; actualizado `CONTINUIDAD.md`.
- [x] **Fase 0 — Seguridad & Hardening:**
  - Redactados secretos en `INFORME_PRUEBAS_1A1.md`, `backend/test_final.py`, `backup.sh` y `healthcheck.sh` (tokens movidos a `.env`).
  - `api_common.py`: verificación `user.active` en `bearer_user()`, `revoke_user_tokens()`, tokens firmados HMAC (`make_preview_token` / `verify_preview_token`).
  - `api_auth.py`: `/auth/logout`, `/auth/forgot-password` con rate-limit y código de confirmación de 6 dígitos (sin sobrescribir clave actual) + `/auth/reset-password`, revocación de tokens en cambios de clave/desactivación, `old_password` obligatorio en `/admin/me`, `/admin/master-info` protegido con `bearer_user()` sin exponer email.
  - `api_maintenance.py`: deshabilitado `/admin/maintenance/execute-sql`, corregido `import fields` y consulta de cumpleaños.
  - `api_companies.py`: `/companies/<id>/preview-config` protegido con token firmado o auth, `base64.b64encode` + validación de tamaño/MIME en subida de logo/fondo, validación estricta de roles (`user_basic` solo lectura), doble ruta `/menus` y `/menus/`.
  - `api_admin.py`: `/admin/payments/create` solo Master, corrección IDOR `vscreens_company_id=False`, normalización de categorías Helpdesk, habilitado Chat Cliente ↔ Master + sincronización `is_read_by_1/2`, soporte `guest_` en `DELETE /admin/chat/conversation/<partner_id>`.
  - `res_users.py`: `create()` solo aplica `vscreens_role` cuando se pasa explícitamente (no pisa grupos de usuarios estándar de Odoo).
  - Eliminado almacenamiento de contraseñas `btoa` en `localStorage` en `frontend-admin` y `app-mobile`.
- [x] **Fase 1A — Backend Odoo, E-Commerce, Crons y AFTVnews Downloader:**
  - `hooks.py` actualizado a firma Odoo 20 `post_init_hook(env)`; los 3 crons (`_cron_check_plan_expiration`, `_cron_send_birthday_greetings`, `seed_venezuelan_holidays`) movidos a `data/cron.xml`.
  - Corregido `vscreens_birthday.py` (usa `vscreens.company.birthday`), `vscreens_calendar_activity.py` (cálculo dinámico de Pascua/Carnaval/Semana Santa), `vscreens_currency.py` (scraping BCV solo en cron, no bloquea polling TV), `vscreens_payment.py` (extiende `valid_until` al confirmar pago y protege `prefix_vat`).
  - Corregido `vscreens_digital_entitlement.py`: `entitled_products |= product` para generar códigos al comprar planes, creación automática de `res.users` (`admin_empresa`) con contraseña temporal en correo de entrega, reset `max_screens=0` en upgrades.
  - Corregido `data/digital_products.xml`: Plan Free `plan_days=7` y nombres alineados con `plans.xml`.
  - Integrado **AFTVnews Downloader**: `aftvnews_code` + botón `action_generate_aftvnews_code` en `product.template`, `_shorten_aftvnews()` en `vscreens.download.code`, y correos actualizados (`email_digital_delivery.xml` y `vscreens_company.py`).
  - Eliminados 5 modelos duplicados en `vscreens_content.py` / `vscreens_registration.py`; añadidas ACLs faltantes y limpiados duplicados en `security/ir.access.csv`.
  - `vscreens_company.py`: añadido `_logger`, filtro `is_active` en `_dump_visual_field()`, orden `_apply_plan_locks()` → `_free_plan_overrides()`, hash determinista `config_hash` en `last_updated`, eliminado `ping_requested_at` de `action_push_config()`.
  - `api_devices.py`: añadido `POST /devices/<uuid>/ack-alert`, rate limit en `/devices/validate-code`, y minimizado `/diag/status`.
- [x] **Fase 1B — App TV 24/7 y Preview Widget:**
  - `frontend-tv/client.js`: eliminado `cueVideoById()` destructivo, corregido `keydown` global en inputs, timer único `schedulePoll` con `AbortController` + caché `localStorage` + reset `failedVideos` al reconectar + offset de reloj desde cabecera `Date`, envío de `ack-alert`, pausa total en `showSuspended()`, soporte Facebook/TikTok y audio en `#file-player`, validación `event.origin` en `postMessage`.
  - `frontend-tv/styles.css`, `index.html` (`?v=3.5`), `Dockerfile` (copia `nginx.conf`).
  - `app-tv/android/`: `MainActivity.java` endurecido (`FLAG_KEEP_SCREEN_ON`, `setMediaPlaybackRequiresUserGesture(false)`, fullscreen inmersivo, guard `onBackPressed`), nuevo `BootReceiver.java` (`BOOT_COMPLETED`), `AndroidManifest.xml` (`landscape`, `WAKE_LOCK`, `ACCESS_NETWORK_STATE`, `usesCleartextTraffic=false`), `network_security_config.xml` limpio (sin `192.168.1.182`), `capacitor.config.json` offline-first.
  - `tv_preview.js` y `vscreens_fields.xml`: `tv_url` dinámico + token `pt` firmado + `t-on-load`.
- [x] **Fase 2 & 3 — Panel Cliente (`frontend-admin`), App Móvil (`app-mobile`) e Infraestructura:**
  - `frontend-admin`: vista `admin_master` redirige a Odoo ERP; `saveAllChanges` filtra solo campos permitidos (resuelve 403); renderizados modales `codeModalData` (vinculación TV), `ForgotPasswordModal` (2 pasos) y `ChangePasswordModal`; corregido `operador_empresa`, `BrandingEditor` (`update`), `Helpdesk` (categorías en minúscula), `MessagingSystem` (`res.ok`), estado `d.is_online` real, preview sin `Date.now()` con token `pt`, `nginx.conf` con `try_files`, Node 20.
  - `app-mobile`: declarado `myDevices` (corrige crash), todos los clientes usan `<MobileApp>` y Master redirige a Odoo ERP, añadida generación de código de vinculación TV en móvil, corregido `ChatPanel.jsx` (`API_BASE`), corregida URL de preview TV, `androidScheme: "https"`, Node 20.
  - `deploy/odoo-vscreens/gateway/nginx.conf`: `vscreens.inverpave.com` enrutado 100% a Odoo Website + `/d/([A-Za-z0-9]{8})` case-insensitive (`~*`).
  - `deploy/odoo-vscreens/docker-compose.yml`: addons `:ro`, healthcheck en Odoo, retirado servicio redundante `vscreens-landing`.
  - `deploy/odoo-vscreens/scripts/entrypoint.sh`: `umask 077`.

- [x] **Despliegue VPS y Validación en TV Real (2026-11-20):**
  - Desplegado commit `d2549ff` (`action_generate_registration_code` devuelve `display_notification` sticky con código de 6 dígitos y registro en chatter) y actualizado módulo `vscreens` en Odoo (`-u vscreens`).
  - Corregido en `frontend-tv/client.js` (commit `c8b6c8e`): limpieza del mensaje `"Sin conexión..."` / `"Reconectando con VScreenS…"` al recibir `404` del servidor (`showRegistration` ahora restaura `"Esperando vinculación…"`), y ampliado timeout de `fetchConfig` de `8.5s` a `15s`.
  - Corregido en `odoo-addons/vscreens/models/vscreens_company.py`: `_logo_url()` evita emitir URLs `127.0.0.1`/`localhost`; fijado `web.base.url` = `https://vscreens.inverpave.com` y `web.base.url.freeze` = `True` en Odoo.
  - Reconstruido `vscreens-tv`, reiniciado `vscreens-odoo` y verificado HTTP 200 en todos los dominios (`vscreens`, `vscreens-app`, `vscreens-api`, `vscreens-tv`, `vscreens-erp`).
- [x] **Mejoras UX/UI TV, Audio, Configurabilidad Total y Reorganización Odoo (2026-11-20):**
  - `frontend-tv`: audio habilitado por defecto para TV (control de volumen físico del televisor + fallback silencioso solo en navegadores desktop restrictivos); fuentes adaptables sin desbordes ni cortes de palabras; redes sociales movidas a la marquesina en movimiento (`show_social_in_ticker`); soporte de imágenes acompañando bloques de texto (`image_url`); animaciones (`slide_up`, `fade`, `slide_left`, `zoom`, `none`) y escalas de fuente configurables; visibilidad configurable de relojes, fechas, badge EN VIVO, subtítulo y texto de pie lateral.
  - `odoo-addons/vscreens`: nuevos campos en `vscreens.sidebar.item` (`image`, `image_url`) y `vscreens.design.settings`; sincronización bidireccional en `vscreens_company.py`; actualización de `tv_preview.js`; reorganización de `company_views.xml` dejando solo el previsualizador arriba y moviendo `Nombre Comercial`, `Información de la Empresa` y `Contacto y redes sociales` dentro de la pestaña `Perfil de Negocio`.
  - `frontend-admin`: controles añadidos en `BrandingEditor` y `SidebarEditor` para animaciones, escala de fuente, imagen en bloques, subtítulo, texto de pie lateral y toggles de visibilidad en TV.
- [x] **Ajustes Reales en TV Física (2026-11-20):**
  - Endpoint público `/companies/<id>/logo` y `/companies/sidebar-item/<id>/image` en `api_companies.py` para servir imágenes reales de Odoo sin caer en `placeholder.png`.
  - Overscan por defecto (`2vw`) configurable (`safety_margin`) para evitar cortes en los extremos laterales del televisor.
  - Auto-ajuste dinámico del nombre comercial (`fitBrandText`) + `word-break: keep-all` para evitar cortes como `VenridesCaf / é`.
  - Nuevas opciones configurables en Odoo y Web: `show_card_frame` (quitar marco de bloques), `show_slide_counter` (ocultar `01/03` por defecto) y `side_footer_animation` (animación del pie lateral).
- [x] **Logo Real, Menú Configurable, Buscador YouTube con Voz y Back x3 en TV (2026-11-20):**
  - `api_companies.py`: lectura directa desde `ir.attachment` (`att.raw`) en `/companies/<id>/logo` para servir los bytes exactos de la imagen subida en Odoo.
  - `show_side_menu` y `side_menu_animation` (`static`, `rotate`, `marquee_vertical`) configurables en Odoo y Panel Web.
  - `api_devices.py` + `frontend-tv`: endpoints `/tv/youtube-search` y `/tv/youtube-related` para buscar videos por texto/voz dentro de la app, reproducir con controles nativos y continuar con videos relacionados sin alterar la playlist configurada.
  - `app-tv/android/`: `MainActivity.java` requiere 3 pulsaciones consecutivas de `Back` para salir (con aviso en la 2ª pulsación y cierre previo de modales web), y `BootReceiver.java` reforzado para arranque automático al encender el TV.
- [x] **Ordenamiento UX por Pestañas (Odoo y Panel Web) + Importación de Productos Odoo Externo (2026-11-20):**
  - `odoo-addons/vscreens`: campos `ds_*` (`related` sobre `design_id`) colocados directamente en su pestaña correspondiente (`Diseño y Marca`, `Contenido TV`, `Barra Lateral`, `Barra Inferior`); eliminada pestaña confusa de ajustes sueltos; nueva pestaña `🔌 Integración Odoo (Productos)` con `vscreens.odoo.remote.product`, `action_fetch_odoo_products` (trae foto, nombre y precio) y `action_send_odoo_products_to_sidebar`.
  - `frontend-admin`: reubicados los controles de Barra Lateral en `SidebarEditor`, los de Barra Inferior en `BottomBarEditor`, y dejados Marca/Overscan/Video en `BrandingEditor`.
- [x] **Barra Inferior Odoo, Botón Visible YouTube y Arranque/Back Nativo Android 10+ (2026-11-20):**
  - `odoo-addons/vscreens`: añadidos en pestaña `Barra Inferior` los controles de aspecto (`bottom_bar_height`, `bottom_bar_border`, `ticker_speed`, `ticker_color`, `ticker_font`, `bcv_font`).
  - `frontend-tv`: botón visible `🔍 Buscar YouTube (OK)` cuando `allow_youtube_control` está activo; apertura con `OK/Enter`; corregido foco D-Pad dentro de `#yt-control` (`refreshNavItems`); aplicados `bottom_bar_bg`/`text`/`border`.
  - `app-tv/android`: interceptación directa de `KEYCODE_BACK` en `dispatchKeyEvent` + `OnBackPressedCallback` (3 pulsaciones para salir); añadido `BootLaunchService` (`ForegroundService` con `fullScreenIntent`) + `SYSTEM_ALERT_WINDOW` para arranque automático tras encendido en Android 10+.
- [x] **YouTube TV Nativo Embebido y Estabilidad de MainActivity (2026-11-20):**
  - `MainActivity.java`: eliminada apertura automática de `ACTION_MANAGE_OVERLAY_PERMISSION` en `onCreate()` que sacaba al usuario de la app; integrado `WebView` nativo de `https://www.youtube.com/tv` (`VScreenSNative.openYouTubeTV`) posicionado en el área de video `#main-stage` con User-Agent Smart TV (búsqueda nativa, voz y reproducción continua sin salir de VScreenS), con retorno automático por `Back` o timeout.
  - `frontend-tv`: conectado `showYoutubeControl()` con `VScreenSNative.openYouTubeTV` en Android TV.
- [x] **Temas Alegóricos/Texturas, Productos Odoo en Lista Separada y Navegación Back en YouTube TV (2026-11-20):**
  - `frontend-tv` + `odoo-addons` + `frontend-admin`: 10 temas visuales con texturas y marcos en barras y área de video (`christmas`, `new_year`, `carnival`, `easter`, `valentine`, `halloween`, `black_friday`, `cafe_wood`, `marble_luxury`, `neon_tech`) + `sidebar_bg_image` y `bottom_bar_bg_image`.
  - `odoo-addons`: switch `show_odoo_products_in_sidebar` + endpoint `/companies/odoo-product/<id>/image` para mostrar/ocultar los productos de `odoo_remote_product_ids` sin mezclarlos con la lista manual `sidebar_items`.
  - `app-tv/android`: `MainActivity.java` envía `Escape` / `history.back()` dentro de la SPA de YouTube TV con 1 pulsación de `Back` (volviendo al buscador/lista) y sale a la playlist con doble `Back` rápido.

### Pendientes Operativos (Requieren acción en VPS / Entorno Android)
1. **Rotar credenciales externas:** contraseña `admin` de Odoo, App Password SMTP (`info.vscreens@inverpave.com`), tokens de Uptime Kuma (y cargarlos en `/opt/vscreens/.env`).
2. **Des-trackear dumps/APKs del índice Git** (en terminal local):
   `git rm --cached -r backups/ backend/backups/ releases/VScreenS_Mobile.apk releases/VScreenS_TV.apk frontend-landing/public/VScreenS.apk frontend-landing/public/VScreenS_TV.apk`
3. **Desplegar en VPS:** `git pull`, actualizar módulo Odoo (`-u vscreens`) y `docker compose up -d --build`.
4. **Configurar código AFTVnews real:** en Odoo → Productos → *VScreenS TV - APK* → pestaña *VScreenS Digital / Plan*, pulsar **"Generar código AFTVnews (Downloader)"** (o registrar la URL de descarga en `https://go.aftvnews.com/` y pegar el código numérico resultante en `Código Downloader (AFTVnews)`).
5. **Compilar APKs firmados** en máquina con JDK 17+ y Android SDK (`npx cap sync android` + `./scripts/build-apks.sh`) y subirlos a `product.template.digital_file` en Odoo.
