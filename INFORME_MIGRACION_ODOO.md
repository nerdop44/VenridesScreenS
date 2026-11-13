# INFORME DE ANÁLISIS Y PLAN DE MIGRACIÓN — VScreenS → Ecosistema 100% Odoo

Fecha: 13 de noviembre de 2026
Autor: Asistente OpenCode
Estado: Análisis completo de versión anterior (FastAPI/SQLAlchemy) y módulo Odoo `vscreens` actual.

---

## 1. RESUMEN EJECUTIVO

Tu backend anterior (FastAPI + SQLAlchemy + PostgreSQL + Redis) era un ecosistema completo de ~3,700 líneas de Python con modelos, servicios, utilidades, controladores y un motor de reglas (Benry). Actualmente el módulo Odoo `vscreens` ya replica **la mayoría** de esa lógica usando herencia de Odoo (sin tocar el core), pero faltan:

1. **Modelos que no se crearon en Odoo**: `vscreens.email.template`, `vscreens.promotion`, `vscreens.affiliate`, `vscreens.calendar.activity`, `vscreens.free.plan.usage`.
2. **Endpoints de mantenimiento maestro** (`/admin/maintenance/*`): listar tablas, leer/borrar/actualizar filas, ejecutar SQL, backup, limpieza.
3. **Servicios externos**: Google Sheets (`sheets_service`), APScheduler (`scheduler_service`) — en Odoo se reemplazan por modelo nativo y `ir.cron`.
4. **Frontend**: la landing ya apunta a Odoo (`vscreens-erp.inverpave.com`), pero el admin panel, la app móvil y la app TV aún apuntan al backend FastAPI separado.

El objetivo es que **todo el ecosistema viva en el módulo Odoo `vscreens`**, sin tocar el core de Odoo, y que la web (landing) se reconstruya con las ventajas nativas de Odoo (portal, sitio web, ecommerce, suscripciones, plantillas de email, helpdesk, analítica, etc.).

---

## 2. INFORME DETALLADO — ¿QUÉ HACÍA LA VERSIÓN ANTERIOR?

### 2.1 Stack Tecnológico (Versión Anterior)

| Componente | Tecnología | Propósito |
|------------|-----------|-----------|
| API | FastAPI (Python 3.11) | REST API para web, admin, móvil, TV |
| ORM | SQLAlchemy 2.0 asyncio | Acceso a PostgreSQL |
| Base de datos | PostgreSQL 15 | Datos de empresas, usuarios, dispositivos, pagos, tickets |
| Caché | Redis 7 | Tasa BCV, rate limiting, sesiones |
| Autenticación | JWT (python-jose, passlib/argon2) | Login, tokens, recuperación de contraseña |
| Email | SMTP (Gmail) | Notificaciones, verificación, mass email |
| Google Sheets | Google Sheets API | Log de contactos, planes, leads de Benry |
| Tareas programadas | APScheduler | Expiraciones, cumpleaños, feriados, saludos automáticos |
| Analítica | Servicio propio (in-memory + archivo JSON) | Visitas, referrers, dispositivos |
| IA/Chat | Benry (reglas, cero LLM) | Chat comercial, detección de intents, handoff humano |
| APK | FileResponse descarga | App TV para Smart TV |
| URL corta | TinyURL API | Enlaces cortos para descarga de APK |

### 2.2 Modelos de Datos (backend/models.py)

| Modelo | Tabla | Campos clave | Relaciones |
|--------|-------|--------------|------------|
| `Company` | `companies` | name, layout, colores, logo_url, video_source, filler_keywords, google_drive_link, priority_content_url, video_playlist (JSON), sidebar_content (JSON), bottom_bar_content (JSON), design_settings (JSON), pause_duration, ad_frequency, plan, max_screens, can_edit_profile, has_edited_profile, sidebar_header_type/value, is_active, valid_until, rif, address, phone, whatsapp, instagram, facebook, tiktok, contact_person, email, client_editable_fields, first_screen_connected_at, plan_activated_at, birthday, auto_notification_settings (JSON) | users, devices, payments, menus, free_plan_usages, messages |
| `User` | `users` | username (email), hashed_password, is_admin, role (admin_master/admin_empresa/operador_empresa/user_basic), permissions (JSON), is_active, temp_password, must_change_password | company, tickets |
| `Device` | `devices` | uuid, name, company_id, last_ping, is_active, last_ip | company |
| `Payment` | `payments` | company_id, amount, currency, payment_method, description, payment_date | company |
| `Menu` | `menus` | company_id, name, price, category, is_available | company |
| `FreePlanUsage` | `free_plan_usages` | uuid, company_id, used_at, expires_at | company |
| `RegistrationCode` | `registration_codes` | code, company_id, expires_at, created_at | company |
| `GlobalAd` | `global_ads` | video_url, video_playlist (JSON), ticker_text, ticker_messages (JSON), ad_scripts (JSON), updated_at | — |
| `Message` | `messages` | sender_id, receiver_id, company_id, subject, body, attachment_url, is_read, is_alert, alert_duration, session_id, created_at | company, sender, receiver |
| `EmailTemplate` | `email_templates` | name, subject, body, default_subject, default_body, is_system, category, is_active, created_at | — |
| `ChatThread` | `chat_threads` | gmail_thread_id, participant_1_id, participant_2_id, last_message_at, last_subject, is_read_by_1/2, is_hidden_by_1/2, created_at | participant_1, participant_2 |
| `BlockedUser` | `blocked_users` | blocker_id, blocked_id, reason, created_at | blocker, blocked |
| `SupportTicket` | `support_tickets` | user_id, category, priority, status, subject, created_at, updated_at | user, messages |
| `TicketMessage` | `ticket_messages` | ticket_id, sender_id, body, created_at, is_internal | ticket, sender |
| `Promotion` | `promotions` | name, description, code, discount_pct, valid_from, valid_to, is_active, created_at | — |
| `Affiliate` | `affiliates` | name, email, code, commission_pct, total_referred, total_earned, is_active, created_at | — |
| `CalendarActivity` | `calendar_activities` | title, description, activity_date, is_holiday, send_auto_greeting, greeting_template_id, created_at | — |
| `Lead` | `leads` | name, email, phone, source, plan_interest, notes, created_at | — |

### 2.3 Endpoints de la API (backend/main.py — 3,700+ líneas)

#### Autenticación
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/login/token` | POST | OAuth2 token (form data) |
| `/auth/login` | POST | Login con JSON, rate limiting |
| `/auth/forgot-password` | POST | Genera contraseña temporal, envía email |
| `/auth/change-password` | POST | Cambia contraseña (requiere autenticación) |

#### Empresas (CRUD completo)
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/companies/` | GET/POST | Listar (solo master) / Crear empresa (solo master) |
| `/companies/{id}` | GET/PATCH | Ver/Actualizar empresa |
| `/companies/{id}/logo` | POST | Subir logo, extrae colores automáticamente |
| `/companies/{id}/sidebar-bg` | POST | Subir fondo de barra lateral |
| `/companies/{id}/toggle` | POST | Activar/suspender empresa |
| `/companies/{id}/credentials` | PATCH | Actualizar usuario/password de la empresa |
| `/companies/{id}/preview-config` | GET | Configuración para previsualizador (sin UUID) |
| `/delete_company/{id}` | DELETE | Eliminar empresa (solo master) |

#### Dispositivos / Pantallas
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/devices/{uuid}/config` | GET | Configuración completa para TV (colores, videos, alertas, BCV, menús, ping) |
| `/devices/generate-code` | POST | Generar código de vinculación (6 dígitos, 10 min) |
| `/devices/validate-code` | POST | Validar código y vincular dispositivo |
| `/devices/{uuid}/rename` | PATCH | Renombrar dispositivo |
| `/diag/ping` | POST | Enviar comando de identificación visual a TV |
| `/admin/devices/` | GET/POST | Listar todos los dispositivos / Vincular manualmente |
| `/admin/devices/{uuid}` | PATCH/DELETE | Actualizar nombre / Eliminar dispositivo |
| `/admin/devices/{uuid}/status` | PATCH | Activar/desactivar dispositivo |
| `/delete_company/{id}/devices` | DELETE | Desvinculación masiva de dispositivos |

#### Pagos
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/admin/payments/` | GET | Listar todos los pagos |
| `/admin/payments/{id}` | GET | Pagos de una empresa |
| `/admin/payments/create` | POST | Crear pago + enviar email con link de APK si está activo |
| `/admin/payments/{id}` | PATCH/DELETE | Actualizar / Eliminar pago |

#### Menús de cliente
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/admin/companies/{id}/menus` | GET/POST | Listar / Crear ítems de menú |
| `/admin/menus/{id}` | DELETE | Eliminar ítem de menú |

#### Mensajería y Chat Interno
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/admin/messages/` | POST | Enviar mensaje |
| `/admin/messages/inbox` | GET | Bandeja de entrada |
| `/admin/messages/{id}/read` | PATCH | Marcar como leído |
| `/admin/chat/conversations` | GET | Conversaciones (internas + sesiones guest de Benry) |
| `/admin/chat/messages/{partner_id}` | GET | Historial de mensajes con un contacto |
| `/admin/chat/send` | POST | Enviar mensaje de chat (interno o guest) |
| `/admin/chat/conversation/{id}` | DELETE | Eliminar conversación (soft delete) |
| `/admin/chat/block` | POST | Bloquear usuario |
| `/admin/chat/unblock` | POST | Desbloquear usuario |
| `/admin/chat/unread-count` | GET | Contar no leídos |
| `/companies/{id}/message` | POST | Enviar alerta en vivo a pantallas |
| `/support/unread-count` | GET | Contar tickets no leídos |

#### Helpdesk / Soporte Técnico (Phase 10)
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/admin/helpdesk/tickets` | GET/POST | Listar / Crear tickets |
| `/admin/helpdesk/tickets/{id}` | GET | Detalle de ticket con mensajes |
| `/admin/helpdesk/tickets/{id}/reply` | POST | Responder ticket |
| `/admin/helpdesk/tickets/{id}/status` | PATCH | Cambiar estado (solo master) |

#### Email Templates y CRM
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/admin/email-templates/` | GET/POST | Listar / Crear plantillas de email |
| `/admin/crm/templates` | GET/POST | Listar / Crear plantillas CRM |
| `/admin/crm/templates/{id}` | DELETE | Eliminar plantilla |
| `/admin/crm/templates/{id}/revert` | POST | Restaurar versión original |
| `/admin/crm/templates/variables` | GET | Lista de variables disponibles |
| `/admin/crm/templates/seed` | POST | Sembrar plantillas por defecto |
| `/admin/crm/mass-email` | POST | Envío masivo a empresas/leads con variables |
| `/admin/crm/send-email-company/{id}` | POST | Enviar email a empresa específica |
| `/admin/crm/leads` | GET | Listar leads |
| `/admin/crm/promotions` | GET/POST | Listar / Crear promociones |
| `/admin/crm/affiliates` | GET/POST | Listar / Crear afiliados |
| `/admin/crm/ecosystem-status` | GET | Estado completo del ecosistema |

#### Calendario y Feriados (Venezuela)
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/admin/crm/calendar` | GET/POST | Listar / Crear actividades |
| `/admin/crm/calendar/{id}` | DELETE | Eliminar actividad |
| `/admin/crm/calendar/holidays` | POST | Sembrar feriados venezolanos (13 fechas fijas) |

#### Mantenimiento Maestro (Solo admin_master)
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/admin/maintenance/tables` | GET | Listar tablas de la BD |
| `/admin/maintenance/table/{name}` | GET | Leer datos de una tabla |
| `/admin/maintenance/table/{name}/{id}` | DELETE/PUT | Borrar / Actualizar fila |
| `/admin/maintenance/execute-sql` | POST | Ejecutar SQL directo |
| `/admin/maintenance/db-cleanup` | POST | Limpiar dispositivos/códigos |
| `/admin/maintenance/backup` | POST | Trigger de backup |
| `/admin/maintenance/run-supervisor` | POST | Ejecutar supervisor de tareas |

#### Formularios Públicos (Landing)
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/forms/contact` | POST | Formulario de contacto (rate limit, honeypot, sanitize, Google Sheets, email) |
| `/api/forms/signup/plan` | POST | Registro de plan (verificación por email, Google Sheets, email de bienvenida) |

#### Descargas
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/downloads/tv/short-url` | GET | URL corta para descarga de APK TV |
| `/downloads/tv` | GET | Descarga del archivo APK |

#### Benry AI (Chat comercial)
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/benry/chat` | POST | Chat con Benry (rate limit, sanitize, detección de intents, handoff, email notificación) |
| `/api/benry/lead` | POST | Guardar lead de Benry (Google Sheets + DB) |
| `/api/benry/session/{id}` | DELETE | Limpiar sesión de chat |

#### Analítica
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/api/analytics/track` | POST | Rastrear visita (página, referrer, dispositivo, país) |
| `/admin/analytics/dashboard` | GET | Dashboard de analítica (visitas, páginas, referrers, dispositivos) |

#### Finanzas
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/finance/bcv` | GET | Tasa de cambio USD/VES (caché + scraping BCV + fallback) |

#### Utilidades / Diagnóstico
| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/diag/status` | GET | Estado de BD y admin |
| `/diag/ping` | POST | Ping a dispositivo TV |
| `/admin/stats/overview` | GET | Estadísticas generales |
| `/admin/debug/stats` | GET | Debug de dispositivos y empresas |
| `/admin/master-info` | GET | Info del admin maestro |
| `/admin/users/` | GET/POST | Listar / Crear usuarios |
| `/admin/users/{id}` | PATCH/DELETE | Actualizar / Eliminar usuario |
| `/admin/users/{id}/password` | PATCH | Cambiar password de usuario |
| `/admin/users/{id}/status` | PATCH | Activar/suspender usuario |
| `/admin/me` | PATCH | Actualizar perfil propio |
| `/admin/global-ad` | GET/POST | Publicidad global (ticker, playlist, scripts) |

### 2.4 Servicios (backend/services/)

| Servicio | Propósito |
|----------|-----------|
| `analytics_service` | Rastrea visitas, referrers, dispositivos; dashboard de analítica |
| `benry_service` | Motor de reglas: detección de intents, FAQ, planes, características, soporte, handoff humano |
| `currency_service` | Tasa BCV con scraping, caché Redis, fallback de emergencia |
| `scheduler_service` | APScheduler: expiraciones diarias (00:05), fechas especiales (08:00), cumpleaños, saludos |
| `sheets_service` | Google Sheets API: log de contactos, planes, leads de Benry |
| `template_service` | Plantillas de email dinámicas con variables (`{{nombre_empresa}}`, `{{plan}}`, etc.) |

### 2.5 Utilidades (backend/utils/)

| Utilidad | Propósito |
|----------|-----------|
| `auth.py` | JWT, hash de contraseñas (argon2), creación/verificación de tokens |
| `bcv.py` | Wrapper de tasa BCV |
| `branding.py` | Extracción de colores de imagen (colorgram) |
| `cleanup_system.py` | Limpieza de logs y backups antiguos (>7 días) |
| `email_sender.py` | SMTP envío de emails (HTML/texto), recuperación de contraseña |
| `url_shortener.py` | Acortamiento de URLs vía TinyURL |

### 2.6 Frontend (Versión Anterior)

| Frontend | URL de API | Tecnología |
|----------|-----------|------------|
| Landing | `https://vscreens-api.inverpave.com` | React + Vite |
| Admin Panel | `https://vscreens-api.inverpave.com` | React + Vite |
| App TV | `https://vscreens-api.inverpave.com` | React + Vite + Capacitor |
| App Móvil | `https://vscreens-api.inverpave.com` | React + Vite + Capacitor |

Todos se conectaban al **backend FastAPI separado**, no a Odoo.

---

## 3. ESTADO ACTUAL — MÓDULO ODOO `vscreens`

### 3.1 Modelos Creados en Odoo (odoo-addons/vscreens/models/)

| Modelo | Nombre Técnico | Hereda | Estado |
|--------|---------------|--------|--------|
| Empresa | `vscreens.company` | `mail.thread`, `mail.activity.mixin` | ✅ Completo |
| Plan | `vscreens.plan` | — | ✅ Completo |
| Característica de plan | `vscreens.plan.feature` | — | ✅ |
| Dispositivo | `vscreens.device` | — | ✅ |
| Código de registro | `vscreens.registration.code` | — | ✅ |
| Uso plan gratuito | `vscreens.free.plan.usage` | — | ❌ **FALTA** (referenciado en registration pero no existe como archivo) |
| Pago | `vscreens.payment` | — | ✅ (vinculado a account.move) |
| Ticket | `vscreens.ticket` | `mail.thread`, `mail.activity.mixin` | ✅ |
| Mensaje de ticket | `vscreens.ticket.message` | — | ✅ |
| Mensaje/Alerta | `vscreens.message` | — | ✅ |
| Chat thread | `vscreens.chat.thread` | — | ✅ |
| Usuario bloqueado | `vscreens.blocked.user` | — | ✅ |
| Mensaje analítica | `vscreens.analytics.visit` | — | ✅ |
| Sesión Benry | `vscreens.benry.session` | — | ✅ |
| Mensaje Benry | `vscreens.benry.message` | — | ✅ |
| Motor Benry | `vscreens.benry` | AbstractModel | ✅ |
| Token API | `vscreens.api.token` | — | ✅ |
| Moneda/BCV | `vscreens.currency` | AbstractModel | ✅ |
| Usuario extendido | `res.users` (herencia) | — | ✅ (`vscreens_company_id`, `vscreens_role`, `vscreens_permissions`) |
| Email Template | `vscreens.email.template` | — | ❌ **FALTA** (referenciado en api_crm.py) |
| Promoción | `vscreens.promotion` | — | ❌ **FALTA** (referenciado en api_crm.py) |
| Afiliado | `vscreens.affiliate` | — | ❌ **FALTA** (referenciado en api_crm.py) |
| Actividad calendario | `vscreens.calendar.activity` | — | ❌ **FALTA** (referenciado en api_crm.py) |

### 3.2 Controladores API (odoo-addons/vscreens/controllers/)

| Controlador | Endpoints implementados | Estado |
|-------------|------------------------|--------|
| `api_public.py` | `/api/plans`, `/finance/bcv`, `/api/logos/<file>`, `/api/forms/contact`, `/api/forms/signup/plan`, `/api/analytics/track`, `/admin/analytics/dashboard`, `/api/benry/chat`, `/api/benry/lead`, `/api/benry/session/<id>`, `/downloads/tv`, `/api/downloads/tv/short-url` | ✅ Completo |
| `api_auth.py` | `/login/token`, `/auth/login`, `/auth/forgot-password`, `/auth/change-password`, `/admin/me`, `/admin/master-info`, `/admin/users/`, `/admin/users/<id>`, `/admin/users/<id>/password` | ✅ Completo |
| `api_companies.py` | `/companies/`, `/companies/<id>`, `/companies/<id>/preview-config`, `/companies/<id>/toggle`, `/companies/<id>/credentials`, `/companies/<id>/logo`, `/companies/<id>/sidebar-bg`, `/admin/companies/<id>/devices`, `/admin/companies/<id>/menus`, `/admin/menus/<id>`, `/companies/<id>/message`, `/admin/companies/<id>` (DELETE) | ✅ Completo |
| `api_crm.py` | `/admin/crm/templates`, `/admin/crm/templates/<id>` (DELETE/revert), `/admin/crm/templates/variables`, `/admin/crm/templates/seed`, `/admin/crm/calendar`, `/admin/crm/calendar/<id>` (DELETE), `/admin/crm/calendar/holidays`, `/admin/crm/leads`, `/admin/crm/promotions`, `/admin/crm/affiliates`, `/admin/crm/ecosystem-status`, `/admin/crm/mass-email`, `/admin/crm/send-email-company/<id>` | ✅ Parcial (referencia modelos que faltan) |
| `api_admin.py` | `/admin/payments`, `/admin/payments/create`, `/admin/chat/*` (conversations, messages, send, unread, block, unblock, delete) | ✅ Completo |
| `api_devices.py` | `/devices/<uuid>/config`, `/devices/validate-code`, `/devices/generate-code`, `/devices/<uuid>/rename`, `/diag/ping`, `/admin/devices/`, `/admin/devices/<uuid>`, `/admin/devices/<uuid>/status`, `/admin/debug/stats`, `/diag/status`, `/support/unread-count` | ✅ Completo |

### 3.3 Datos Demo Cargados (odoo-addons/vscreens/data/)

| Archivo | Contenido | Estado |
|---------|-----------|--------|
| `plans.xml` | Planes free/basic/plus/ultra/empresarial con precios y características | ✅ |
| `products.xml` | Producto servicio suscripción | ✅ |
| `global_ad.xml` | Publicidad global por defecto | ✅ |
| `cron.xml` | Tareas programadas | ✅ |

---

## 4. TABLA COMPARATIVA — ANTES (FastAPI) vs DESPUÉS (Odoo)

| Característica | Versión Anterior (FastAPI) | Nueva Versión (Odoo `vscreens`) | ¿Migrado? | Notas |
|---------------|---------------------------|--------------------------------|-----------|-------|
| **Empresas/Clientes** | `Company` (SQLAlchemy) | `vscreens.company` (hereda mail.thread) | ✅ Sí | Odoo añade chatter, actividades, seguidores |
| **Usuarios y Roles** | `User` (SQLAlchemy) | `res.users` (herencia con `vscreens_company_id`, `vscreens_role`) | ✅ Sí | Odoo nativo: grupos, permisos, portal |
| **Planes y Precios** | Campo `plan` string | `vscreens.plan` + `vscreens.plan.feature` | ✅ Sí | Modelo dedicado, características por plan |
| **Pagos** | `Payment` (SQLAlchemy) | `vscreens.payment` + `account.move` | ✅ Sí | Vinculado a facturación Odoo |
| **Facturación Digital TFHKA** | — | `l10n_ve_invoice_digital` | ✅ Sí | Probado: correlativo `00-00000057` |
| **Bimoneda USD/VES** | `tax_today` campo | `account_dual_currency` + `l10n_ve_rate` | ✅ Sí | Tasa BCV 911,6243 cargada, cron 01:00 |
| **Dispositivos/Pantallas** | `Device` (SQLAlchemy) | `vscreens.device` | ✅ Sí | UUID, ping, código de registro |
| **Códigos de Vinculación** | `RegistrationCode` | `vscreens.registration.code` | ✅ Sí | 6 dígitos, 10 min, límite de pantallas |
| **CRM / Leads** | `Lead` (SQLAlchemy) | `crm.lead` (heredado de Odoo) | ✅ Sí | `vscreens_plan_interest`, `vscreens_source_detail` |
| **Helpdesk / Tickets** | `SupportTicket` + `TicketMessage` | `vscreens.ticket` + `vscreens.ticket.message` | ✅ Sí | Estados, prioridad, categorías, mail.thread |
| **Mensajes / Alertas** | `Message` (SQLAlchemy) | `vscreens.message` | ✅ Sí | `is_alert`, `alert_duration`, session_id |
| **Chat Interno** | `ChatThread` + `BlockedUser` | `vscreens.chat.thread` + `vscreens.blocked.user` | ✅ Sí | Hilos, lecturas, bloqueos |
| **Publicidad Global** | `GlobalAd` (SQLAlchemy) | `vscreens.global.ad` | ✅ Sí | Ticker, playlist, scripts |
| **Menús de Cliente** | `Menu` (SQLAlchemy) | `vscreens.menu.item` | ✅ Sí | Categoría, precio, disponibilidad |
| **Analítica** | `analytics_service` (in-memory) | `vscreens.analytics.visit` | ✅ Sí | Persistente en BD |
| **Benry IA** | `benry_service` (reglas) | `vscreens.benry` + sesiones + mensajes | ✅ Sí | Motor de reglas, intents, FAQ, handoff |
| **Tasa BCV** | `currency_service` (Redis + scraping) | `vscreens.currency` + `ir.config_parameter` | ✅ Sí | Caché en parámetros Odoo, scraping BCV |
| **Formularios Web** | `/api/forms/contact`, `/api/forms/signup/plan` | Endpoints públicos en Odoo | ✅ Sí | Rate limit, honeypot, sanitize |
| **Planes Públicos** | `/api/plans` | `/api/plans` (Odoo) | ✅ Sí | HTTP 200 verificado |
| **Descarga APK** | `/downloads/tv` | `/downloads/tv` (Odoo) | ✅ Sí | Sirve archivo desde releases |
| **URL corta APK** | TinyURL API | `/api/downloads/tv/short-url` (Odoo) | ✅ Sí | |
| **Email Templates** | `EmailTemplate` (SQLAlchemy) | `vscreens.email.template` | ❌ **FALTA** | Modelo no creado, referenciado en api_crm |
| **Promociones** | `Promotion` (SQLAlchemy) | `vscreens.promotion` | ❌ **FALTA** | Modelo no creado, referenciado en api_crm |
| **Afiliados** | `Affiliate` (SQLAlchemy) | `vscreens.affiliate` | ❌ **FALTA** | Modelo no creado, referenciado en api_crm |
| **Calendario/Feriados** | `CalendarActivity` (SQLAlchemy) | `vscreens.calendar.activity` | ❌ **FALTA** | Modelo no creado, referenciado en api_crm |
| **Uso Plan Gratuito** | `FreePlanUsage` (SQLAlchemy) | `vscreens.free.plan.usage` | ❌ **FALTA** | Referenciado en registration.code |
| **Mantenimiento Maestro** | `/admin/maintenance/*` | — | ❌ **FALTA** | Tablas, SQL, backup, cleanup |
| **Google Sheets** | `sheets_service` | — | ❌ **FALTA** | Reemplazable por `mail.template` + reporte Odoo |
| **APScheduler** | `scheduler_service` | `ir.cron` (nativo Odoo) | ✅ Parcial | Cron ya existe para BCV; faltan expiraciones/cumpleaños |
| **Colorgram** | `branding.py` | `_extract_colors` en api_companies | ✅ Sí | PIL en Odoo |
| **Email SMTP** | `email_sender.py` | `mail.mail` (nativo Odoo) | ✅ Sí | Odoo tiene servidor de salida nativo |
| **JWT Auth** | `auth.py` (python-jose) | `vscreens.api.token` + `res.users.authenticate` | ✅ Sí | Odoo auth nativo + tokens personalizados |
| **Web/Landing** | Conectada a FastAPI | Conectada a Odoo (`vscreens-erp.inverpave.com`) | ✅ Sí | .env.production y .env.development actualizados |
| **Admin Panel** | Conectado a FastAPI | — | ❌ **PENDIENTE** | Aún apunta a `vscreens-api.inverpave.com` |
| **App TV** | Conectado a FastAPI | Conectado a Odoo (`/devices/<uuid>/config`) | ✅ Sí | TV ya usa Odoo |
| **App Móvil** | Conectado a FastAPI | — | ❌ **PENDIENTE** | Aún apunta a backend FastAPI |

---

## 5. ANÁLISIS DE CANASAAS — LÓGICA DE SUSCRIPCIONES CON DESPLIEGUES AUTOMÁTICOS

### 5.1 Arquitectura CanalSaaS (de Obsidian_Vault/CanalSaaS.md)

CanalSaaS es una plataforma SaaS basada en **Odoo 18 Community** con arquitectura multi-DB:

- **Una instancia Odoo** con múltiples bases de datos PostgreSQL:
  - `control` — plataforma/portal (gestión de tenants, planes, facturación)
  - `master_template` — plantilla base para tenants (limpia, sin demo, con localización VE)
  - Una DB por tenant (clonada de `master_template`)

- **Provisión automática de tenants**:
  - `canalsaas.tenant` — subdomain, db_name, state (draft→active→suspended), acciones: provision/reactivate/purge
  - `canalsaas.plan` — recurrencia (mensual/anual), pricelist_id, módulos incluidos, precio por usuario
  - `canalsaas.subscription` — next_billing_date, ciclo de vida, check_overdue_and_suspend, cambio de plan
  - `canalsaas.provision.engine` — `provision_tenant()` (CREATE DATABASE TEMPLATE master_template + filestore + post-config), `set_admin_password()`

- **Routing multi-DB**: `ir_http_patch` con `X-Odoo-dbfilter` por Host/dominio. Nginx proxyea a Odoo con el dbfilter correspondiente.

- **Planes SaaS**: Básico $35, Profesional $65, Enterprise $120 USD/mes.

- **Demo por tiempo limitado**: Los tenants se aprovisionan con `valid_until` (prueba gratuita), y al vencerse se suspenden automáticamente.

### 5.2 Lógica Replicable para VScreenS

| Concepto CanalSaaS | Aplicación a VScreenS |
|-------------------|----------------------|
| Una instancia Odoo multi-DB | Una instancia Odoo `vscreens-erp` con módulo `vscreens` (multi-empresa nativo de Odoo) |
| `canalsaas.tenant` | `vscreens.company` (ya existe, con `valid_until`, `is_active`, `plan_id`) |
| `canalsaas.plan` | `vscreens.plan` (ya existe, con precios, características, max_screens) |
| `canalsaas.subscription` | `vscreens.payment` + `account.move` + `valid_until` automático al pagar |
| `provision_tenant()` | Al crear empresa en Odoo: se crea el `res.partner`, el `res.users` (admin + operador), y se asigna el plan |
| `set_admin_password()` | Odoo nativo: `res.users` con `password` |
| Routing por dbfilter/dominio | Odoo nativo: `dbfilter` por subdominio, o usar `vscreens.company` con `website_url` |
| Demo por tiempo limitado | `valid_until` en `vscreens.company` (7 días trial para plan free), suspensión automática al expirar |
| Suspensión por falta de pago | Cron que revisa `valid_until` y pone `is_active = False` |

### 5.3 ¿Por qué Odoo es superior para este caso?

Odoo tiene **multi-empresa nativo**, **portal de clientes**, **sitio web builder**, **ecommerce**, **suscripciones (`sale_subscription`)**, **helpdesk nativo**, **plantillas de email**, **reportes**, y **analítica** — todo integrado sin necesidad de un backend separado. El módulo `vscreens` hereda de todo esto sin tocar el core.

---

## 6. PLAN DE MIGRACIÓN — TODO A ODOO `vscreens`

### Fase 1: Crear modelos faltantes (sin tocar core)

| Modelo a crear | Archivo | Propósito |
|---------------|---------|-----------|
| `vscreens.email.template` | `models/vscreens_email_template.py` | Plantillas de email con variables, versión sistema vs usuario |
| `vscreens.promotion` | `models/vscreens_promotion.py` | Promociones con código, descuento, vigencia |
| `vscreens.affiliate` | `models/vscreens_affiliate.py` | Afiliados con comisión, código de referencia |
| `vscreens.calendar.activity` | `models/vscreens_calendar_activity.py` | Actividades, feriados venezolanos, saludos automáticos |
| `vscreens.free.plan.usage` | `models/vscreens_free_plan_usage.py` | Uso de prueba gratuita por dispositivo UUID |

### Fase 2: Crear endpoints de mantenimiento maestro

| Endpoint | Propósito | Implementación en Odoo |
|----------|-----------|------------------------|
| `/admin/maintenance/tables` | Listar tablas | Consultar `ir.model` |
| `/admin/maintenance/table/{name}` | Leer datos | `request.env[model].search_read()` |
| `/admin/maintenance/execute-sql` | Ejecutar SQL | `self.env.cr.execute()` (solo admin_master) |
| `/admin/maintenance/db-cleanup` | Limpiar dispositivos | `vscreens.device.unlink()` + códigos expirados |
| `/admin/maintenance/backup` | Backup | Llamar a script de pg_dump del sistema |

### Fase 3: Reemplazar servicios externos por nativos Odoo

| Servicio anterior | Reemplazo Odoo |
|------------------|----------------|
| `sheets_service` (Google Sheets) | `mail.template` + reportes de Odoo + `ir.actions.report` |
| `scheduler_service` (APScheduler) | `ir.cron` (ya existe para BCV; agregar expiraciones, cumpleaños, feriados) |
| `currency_service` (Redis) | `vscreens.currency` + `ir.config_parameter` (ya implementado) |
| `email_sender.py` (SMTP) | `mail.mail` (servidor de salida nativo de Odoo) |
| `url_shortener.py` (TinyURL) | Campo `short_url` computado o integración propia |

### Fase 4: Conectar todos los frontends a Odoo

| Frontend | URL API actual | URL API objetivo | Acción |
|----------|---------------|-----------------|--------|
| Landing | ✅ `vscreens-erp.inverpave.com` | Ya conectado | Hecho |
| Admin Panel | `vscreens-api.inverpave.com` | `vscreens-erp.inverpave.com` | Cambiar `.env.production` y rebuild |
| App TV | ✅ `vscreens-erp.inverpave.com` | Ya conectado (devices config) | Hecho |
| App Móvil | `vscreens-api.inverpave.com` | `vscreens-erp.inverpave.com` | Cambiar y rebuild APK |

### Fase 4b: Reconstruir la landing con ventajas de Odoo

La landing actual es un SPA React separado. Para aprovechar Odoo al 100%:

1. **Odoo Website Builder**: Crear el sitio web de VScreenS dentro de Odoo (`website` module), con páginas: inicio, planes, precios, descargas, contacto, legal.
2. **Odoo eCommerce / Suscripciones**: Usar `sale_subscription` para que los clientes se suscriban a planes directamente desde la web, con pago automático y activación de cuenta.
3. **Portal de clientes**: Cada empresa tiene su portal en Odoo donde gestiona pantallas, ve facturas, abre tickets, descarga APKs.
4. **Formularios nativos**: `website_form` para contacto y registro de planes, sin necesidad de endpoints API separados.
5. **Benry integrado**: El chat de Benry vive dentro del portal/web de Odoo, usando `vscreens.benry` y `vscreens.message`.

### Fase 5: Lógica de suscripciones con despliegues automáticos (estilo CanalSaaS)

| Flujo | Implementación en Odoo |
|-------|------------------------|
| Cliente se registra en la web | `crm.lead` → se crea `vscreens.company` + `res.users` (admin + operador) automáticamente |
| Plan gratuito (trial) | `valid_until` = ahora + 7 días; `is_active = True` |
| Cliente paga | `vscreens.payment` → `account.move` (factura) → se extiende `valid_until` según el plan |
| Plan vence | Cron diario revisa `valid_until < hoy` → `is_active = False` → pantallas dejan de recibir config |
| Demo por tiempo limitado | Mismo flujo que trial gratuito; al expirar, se suspende la empresa |
| Despliegue automático | Al activarse la empresa, se generan credenciales y código de registro para la TV |

---

## 7. RESUMEN DE ACCIONES INMEDIATAS

1. **Crear los 5 modelos faltantes** en `odoo-addons/vscreens/models/`
2. **Agregar endpoints de mantenimiento** en un nuevo controlador `api_maintenance.py`
3. **Cambiar `.env.production` y `.env.development` del frontend-admin** a `vscreens-erp.inverpave.com`
4. **Cambiar la URL de API de la app móvil** a `vscreens-erp.inverpave.com`
5. **Reconstruir la landing** usando Odoo Website + eCommerce + suscripciones
6. **Configurar `ir.cron`** para: expiración de planes, cumpleaños, feriados venezolanos, saludos automáticos
7. **Desplegar todo en el VPS** sin afectar el stack Odoo actual (usa la misma DB `vscreens`)

¿Quieres que proceda con la Fase 1 (crear modelos faltantes) y Fase 2 (endpoints de mantenimiento) ahora mismo?
