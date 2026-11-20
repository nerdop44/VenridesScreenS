from datetime import timedelta
import ast
import hashlib
import json
import logging
import requests

from odoo import api, fields, models
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


class VScreenSCompany(models.Model):
    _name = "vscreens.company"
    _description = "Empresa / cliente VScreenS"
    _inherit = ["mail.thread", "mail.activity.mixin"]
    _order = "name"
    _rec_name = "name"

    name = fields.Char(string="Nombre comercial", required=True, tracking=True)
    partner_id = fields.Many2one("res.partner", string="Contacto / facturación", ondelete="set null")
    plan_id = fields.Many2one("vscreens.plan", string="Plan", required=True, tracking=True)
    plan_code = fields.Char(related="plan_id.code", string="Código de plan", store=True)
    max_screens = fields.Integer(
        string="Máximo de pantallas",
        default=2,
        help="Si es 0, se usa el límite del plan. Si el plan es 0, es ilimitado.",
    )
    is_active = fields.Boolean(string="Activa", default=True, tracking=True)
    valid_until = fields.Datetime(string="Válida hasta", tracking=True)
    plan_activated_at = fields.Datetime(string="Plan activado el")
    first_screen_connected_at = fields.Datetime(string="Primera pantalla conectada el")

    can_edit_profile = fields.Boolean(string="Puede editar perfil", default=False)
    has_edited_profile = fields.Boolean(string="Ya editó perfil", default=False)
    client_editable_fields = fields.Char(
        string="Campos editables por el cliente",
        default="",
        help="Lista separada por comas: name,rif,address,phone,email,whatsapp,instagram,facebook,tiktok",
    )

    # Información de negocio
    rif = fields.Char(string="RIF / Documento")
    address = fields.Text(string="Dirección")
    phone = fields.Char(string="Teléfono")
    whatsapp = fields.Char(string="WhatsApp")
    instagram = fields.Char(string="Instagram")
    facebook = fields.Char(string="Facebook")
    tiktok = fields.Char(string="TikTok")
    contact_person = fields.Char(string="Persona de contacto")
    email = fields.Char(string="Email")
    birthday = fields.Date(string="Cumpleaños")
    is_email_verified = fields.Boolean(default=False)
    is_phone_verified = fields.Boolean(default=False)
    email_verification_code = fields.Char()

    # Branding y contenido
    layout_type = fields.Char(default="layout-a")
    primary_color = fields.Char(default="#1a202c")
    secondary_color = fields.Char(default="#2d3748")
    accent_color = fields.Char(default="#4a5568")
    logo_url = fields.Char(string="URL del logo")
    logo = fields.Binary(string="Logo", attachment=True)
    logo_filename = fields.Char()
    sidebar_bg = fields.Binary(string="Fondo de barra lateral", attachment=True)
    sidebar_bg_filename = fields.Char()
    video_source = fields.Selection(
        [("youtube", "YouTube"), ("drive", "Google Drive")],
        default="youtube",
        string="Fuente de video",
    )
    filler_keywords = fields.Char(default="nature, coffee", string="Palabras clave de relleno")
    google_drive_link = fields.Char(string="Enlace de Google Drive")
    priority_content_url = fields.Char(string="Contenido prioritario")
    video_playlist = fields.Json(string="Playlist de videos", default=list)
    scheduled_videos = fields.Json(
        string="Videos programados",
        default=list,
        help="Lista de objetos: {url, title, start, end, days}. start/end en formato YYYY-MM-DD HH:MM y days como lista de días (0=lunes … 6=domingo). Si se omiten, aplica siempre.",
    )
    sidebar_content = fields.Json(string="Contenido de barra lateral", default=list)
    bottom_bar_content = fields.Json(string="Contenido de barra inferior", default=dict)
    design_settings = fields.Json(string="Ajustes de diseño", default=dict)
    pause_duration = fields.Integer(string="Duración de pausa (min)", default=10)
    ad_frequency = fields.Integer(string="Frecuencia de anuncios (s)", default=30)
    allow_tv_youtube_control = fields.Boolean(
        string="Permitir cambiar videos desde la TV",
        default=False,
        help="Si está activo, desde el control remoto de la TV se puede buscar y "
             "reproducir un video de YouTube temporalmente. Al desactivarlo (o al "
             "cumplirse el tiempo), la TV vuelve a su playlist habitual.",
    )
    tv_youtube_control_minutes = fields.Integer(
        string="Minutos de control desde la TV",
        default=30,
        help="Tiempo máximo que se mantiene un video elegido desde el control remoto.",
    )

    # --- Enlace configurable con el Odoo de facturación / inventario del cliente ---
    odoo_link_enabled = fields.Boolean(string="Mostrar enlace Odoo en la TV", default=False)
    odoo_link_label = fields.Char(string="Etiqueta del enlace", default="Facturación")
    odoo_link_url = fields.Char(string="URL base de Odoo", help="Debe empezar con https://")
    odoo_link_db = fields.Char(string="Base de datos de Odoo")
    odoo_link_user = fields.Char(string="Usuario de Odoo")
    odoo_link_password = fields.Char(string="Contraseña / API key", groups="vscreens.group_vscreens_master")
    odoo_link_model = fields.Selection(
        [
            ("account.move", "Facturas"),
            ("sale.order", "Pedidos"),
            ("purchase.order", "Compras"),
            ("stock.picking", "Albaranes / Inventario"),
            ("crm.lead", "Oportunidades"),
            ("res.partner", "Contactos"),
        ],
        string="Modelo a mostrar",
        default="account.move",
    )
    odoo_link_domain = fields.Char(
        string="Filtro Odoo (domain)",
        default="[]",
        help="Ejemplo: [('state','=','posted')]. Solo se permite una lista literal segura.",
    )
    odoo_link_fields = fields.Char(
        string="Campos a mostrar",
        default="name:Referencia,amount_total:Monto",
        help="Formato campo:etiqueta, separado por comas. Ej: name:Referencia,amount_total:Monto",
    )
    odoo_link_limit = fields.Integer(string="Máximo de registros", default=5)
    odoo_link_refresh = fields.Integer(string="Actualizar cada (minutos)", default=60)
    odoo_link_icon = fields.Char(string="Icono (FontAwesome)", default="fa-file-text")
    odoo_link_color = fields.Char(string="Color del enlace", default="#c8ff00")
    odoo_link_data = fields.Json(string="Datos del enlace Odoo", copy=False)
    odoo_link_error = fields.Char(string="Último error del enlace", copy=False)
    odoo_link_last_sync = fields.Datetime(string="Última sincronización", copy=False)
    sidebar_header_type = fields.Selection(
        [("text", "Texto"), ("banner", "Banner")], default="text", string="Tipo de encabezado"
    )
    sidebar_header_value = fields.Char(string="Valor del encabezado")

    # ============================================================================
    # CONTROLES VISUALES (One2many hacia modelos auxiliares)
    # Estos campos reemplazan la edición directa de JSON en la UI.
    # Los campos JSON originales se mantienen para compatibilidad con la API.
    # ============================================================================
    playlist_items = fields.One2many(
        "vscreens.playlist.item",
        "company_id",
        string="Ítems de Playlist",
    )
    scheduled_video_items = fields.One2many(
        "vscreens.scheduled.video.item",
        "company_id",
        string="Videos Programados",
    )
    sidebar_items = fields.One2many(
        "vscreens.sidebar.item",
        "company_id",
        string="Ítems de Barra Lateral",
    )
    bottom_bar_items = fields.One2many(
        "vscreens.bottom.bar.item",
        "company_id",
        string="Ítems de Barra Inferior",
    )
    design_settings_id = fields.One2many(
        "vscreens.design.settings",
        "company_id",
        string="Ajustes de Diseño",
    )
    # Campos booleanos para notificaciones (se guardan en auto_notification_settings)
    notification_welcome = fields.Boolean(
        string="Bienvenida",
        default=True,
    )
    notification_billing = fields.Boolean(
        string="Cobranza",
        default=True,
    )
    notification_expiry_reminders = fields.Boolean(
        string="Vencimiento",
        default=True,
    )
    notification_birthday_greetings = fields.Boolean(
        string="Cumpleaños",
        default=True,
    )
    notification_holiday_greetings = fields.Boolean(
        string="Festividades",
        default=True,
    )

    auto_notification_settings = fields.Json(
        string="Notificaciones automáticas",
        default=lambda self: {
            "welcome": True,
            "billing": True,
            "expiry_reminders": True,
            "birthday_greetings": True,
            "holiday_greetings": True,
        },
    )
    notes = fields.Text(string="Notas internas")

    user_ids = fields.One2many("res.users", "vscreens_company_id", string="Usuarios")
    device_ids = fields.One2many("vscreens.device", "company_id", string="Pantallas")
    payment_ids = fields.One2many("vscreens.payment", "company_id", string="Pagos")
    menu_item_ids = fields.One2many("vscreens.menu.item", "company_id", string="Menú")
    vscreens_message_ids = fields.One2many("vscreens.message", "company_id", string="Mensajes VScreenS")
    ticket_ids = fields.One2many("vscreens.ticket", "company_id", string="Tickets")

    total_screens = fields.Integer(string="Pantallas totales", compute="_compute_screen_counts")
    active_screens = fields.Integer(string="Pantallas activas", compute="_compute_screen_counts")
    online_screens = fields.Integer(string="Pantallas transmitiendo", compute="_compute_screen_counts")
    offline_screens = fields.Integer(string="Pantallas sin señal", compute="_compute_screen_counts")
    max_screens_effective = fields.Integer(string="Límite efectivo", compute="_compute_max_screens")

    # Versión de configuración: se incrementa al enviar cambios a las pantallas.
    config_version = fields.Integer(string="Versión de configuración", default=1, copy=False)
    # Pantallas seleccionadas para el envío manual desde el panel de previsualización.
    push_device_ids = fields.Many2many(
        "vscreens.device",
        "vscreens_company_push_device_rel",
        "company_id",
        "device_id",
        string="Pantallas destino",
    )

    @api.depends("device_ids", "device_ids.is_active", "device_ids.last_ping")
    def _compute_screen_counts(self):
        for company in self:
            devices = company.device_ids
            company.total_screens = len(devices)
            company.active_screens = len(devices.filtered("is_active"))
            company.online_screens = len(devices.filtered("is_online"))
            company.offline_screens = company.total_screens - company.online_screens

    @api.depends("max_screens", "plan_id.max_screens")
    def _compute_max_screens(self):
        for company in self:
            if company.max_screens:
                company.max_screens_effective = company.max_screens
            else:
                company.max_screens_effective = company.plan_id.max_screens or 0

    def _is_plan_unlimited(self):
        self.ensure_one()
        return self.max_screens_effective == 0

    def _can_add_device(self):
        self.ensure_one()
        if self._is_plan_unlimited():
            return True
        return len(self.device_ids) < self.max_screens_effective

    def _is_expired(self):
        self.ensure_one()
        if not self.valid_until:
            return False
        return self.valid_until < fields.Datetime.now()

    def _is_service_active(self):
        self.ensure_one()
        return self.is_active and not self._is_expired()

    def _get_global_ad(self):
        return self.env["vscreens.global.ad"].sudo().search([("active", "=", True)], order="write_date desc", limit=1)

    def _get_active_alert(self):
        self.ensure_one()
        return self.env["vscreens.message"].sudo().search(
            [("company_id", "=", self.id), ("is_alert", "=", True), ("is_read", "=", False)],
            order="create_date desc",
            limit=1,
        )

    def _get_menus(self):
        self.ensure_one()
        return self.menu_item_ids.filtered("is_available")

    def _iso(self, value):
        if not value:
            return None
        return fields.Datetime.to_string(value)

    def _free_plan_overrides(self, config):
        self.ensure_one()
        if (self.plan_code or "").lower() != "free":
            return config
        socials = {
            key: config["bottom_bar_content"][key]
            for key in ("whatsapp", "instagram", "phone")
            if config.get("bottom_bar_content", {}).get(key)
        }
        gad = self._get_global_ad()
        if not gad:
            config["bottom_bar_content"] = {
                "static": "VScreenS Pantallas Inteligentes",
                **socials,
            }
            return config

        playlist = [v for v in (gad.video_playlist or []) if v and str(v).strip()]
        if not playlist and gad.video_url:
            playlist = [gad.video_url]
        if playlist:
            # La publicidad global no reemplaza el contenido prioritario del cliente.
            if not config.get("priority_content_url"):
                config["priority_content_url"] = playlist[0]
            config["priority_playlist"] = playlist

        ticker_messages = gad.ticker_messages or []
        if not ticker_messages and gad.ticker_text:
            ticker_messages = [gad.ticker_text]
        if ticker_messages:
            config["bottom_bar_content"] = {
                "static": ticker_messages[0],
                "messages": ticker_messages,
                "font_size": "1.5rem",
                "color": "#fbbf24",
                "weight": "bold",
                **socials,
            }
        if gad.ad_scripts:
            config["ad_scripts"] = gad.ad_scripts

        if self.valid_until:
            days = (self.valid_until - fields.Datetime.now()).days
            if 0 <= days <= 15:
                alert_msg = f"⚠️ Tu prueba gratuita vence en {days} días. ¡Suscríbete en vscreens.inverpave.com!"
                bottom = config.get("bottom_bar_content") or {}
                if isinstance(bottom, dict) and "messages" in bottom:
                    bottom["messages"].append(alert_msg)
                    config["bottom_bar_content"] = bottom
                else:
                    config["bottom_bar_content"] = {
                        "static": alert_msg,
                        "messages": [alert_msg],
                        "font_size": "1.4rem",
                        "color": "#ef4444",
                        "weight": "bold",
                    }
        return config

    def unlink(self):
        for company in self:
            users = self.env["res.users"].sudo().search([("vscreens_company_id", "=", company.id)])
            users = users.filtered(lambda u: not u.has_group("vscreens.group_vscreens_master"))
            if users:
                users.unlink()
        return super().unlink()

    @api.model
    def _cron_check_plan_expiration(self):
        """Cron diario: suspende empresas cuyo plan ha vencido."""
        companies = self.sudo().search([("is_active", "=", True), ("valid_until", "!=", False)])
        expired = 0
        now = fields.Datetime.now()
        for company in companies:
            if company.valid_until and company.valid_until < now:
                company.sudo().write({"is_active": False})
                expired += 1
        _logger = logging.getLogger(__name__)
        _logger.info("Cron expiración planes: %d empresas suspendidas", expired)
        return expired

    def _plan_allows(self, feature):
        self.ensure_one()
        if not self.plan_id:
            return True
        return bool(getattr(self.plan_id, feature, True))

    def _apply_plan_locks(self, config):
        self.ensure_one()
        if not self._plan_allows('allow_sidebar'):
            config['sidebar_content'] = []
        if not self._plan_allows('allow_bottom_bar'):
            config['bottom_bar_content'] = {}
        if not self._plan_allows('allow_video_playlist'):
            config['video_playlist'] = []
        if not self._plan_allows('allow_priority_content'):
            config['priority_content_url'] = None
        if not self._plan_allows('allow_bcv'):
            config['bcv_rate'] = 0.0
        if not self._plan_allows('allow_third_party_ads'):
            config.pop('ad_scripts', None)
        if not self._plan_allows('allow_custom_branding'):
            config['primary_color'] = '#1a202c'
            config['secondary_color'] = '#2d3748'
            config['accent_color'] = '#4a5568'
            config['logo_url'] = None
        return config

    def _active_scheduled_videos(self):
        """Devuelve los videos programados vigentes en este momento.

        Cada elemento puede traer: url, title, start, end y days.
        - start/end: 'YYYY-MM-DD HH:MM' o ISO 8601. Si faltan, no limitan.
        - days: lista de enteros con 0=lunes … 6=domingo. Si falta, aplica todos.
        """
        self.ensure_one()
        now = fields.Datetime.now()
        active = []
        for item in (self.scheduled_videos or []):
            if isinstance(item, str):
                item = {"url": item}
            if not isinstance(item, dict):
                continue
            url = (item.get("url") or "").strip()
            if not url:
                continue
            start = item.get("start")
            end = item.get("end")
            days = item.get("days")
            try:
                if start and now < fields.Datetime.to_datetime(start):
                    continue
                if end and now > fields.Datetime.to_datetime(end):
                    continue
                if days:
                    normalized = {int(d) for d in days if str(d).lstrip("-").isdigit()}
                    if normalized and now.weekday() not in normalized:
                        continue
            except (ValueError, TypeError):
                # Si la programación viene mal formada, se ignora la ventana
                # en lugar de bloquear el contenido del cliente.
                pass
            entry = dict(item)
            entry["url"] = url
            active.append(entry)
        return active

    # ------------------------------------------------------------------
    # Sincronización controles visuales -> JSON que consume la TV
    # ------------------------------------------------------------------
    _VISUAL_JSON_MAP = {
        "playlist_items": "video_playlist",
        "scheduled_video_items": "scheduled_videos",
        "sidebar_items": "sidebar_content",
        "bottom_bar_items": "bottom_bar_content",
        "design_settings_id": "design_settings",
    }
    _NOTIFICATION_FIELDS = {
        "notification_welcome": "welcome",
        "notification_billing": "billing",
        "notification_expiry_reminders": "expiry_reminders",
        "notification_birthday_greetings": "birthday_greetings",
        "notification_holiday_greetings": "holiday_greetings",
    }

    def _dump_visual_field(self, field_name):
        """Convierte un campo visual (One2many) al JSON que consume la TV."""
        self.ensure_one()
        if field_name == "playlist_items":
            # La TV reproduce una lista de URLs activas (formato histórico del panel web).
            return [item.url for item in self.playlist_items if item.url and item.is_active]
        if field_name == "scheduled_video_items":
            return [
                {
                    "url": item.url,
                    "title": item.title or "",
                    "start": fields.Datetime.to_string(item.start_datetime) if item.start_datetime else False,
                    "end": fields.Datetime.to_string(item.end_datetime) if item.end_datetime else False,
                    "duration": item.duration or 300,
                    "scheduled": True,
                }
                for item in self.scheduled_video_items
                if item.url and item.is_active
            ]
        if field_name == "sidebar_items":
            base = self.env["ir.config_parameter"].sudo().get_str("web.base.url", "").rstrip("/")
            if not base or "127.0.0.1" in base or "localhost" in base:
                base = "https://vscreens-api.inverpave.com"
            result = []
            for item in self.sidebar_items:
                if not ((item.value or item.label) and item.is_active):
                    continue
                img_url = item.image_url or False
                if not img_url and item.image:
                    stamp = int(item.write_date.timestamp()) if item.write_date else 0
                    img_url = f"{base}/web/image/vscreens.sidebar.item/{item.id}/image?unique={stamp}"
                result.append({
                    "type": "text",
                    "label": item.label or "",
                    "value": item.value or item.label or "",
                    "icon": item.icon or False,
                    "color": item.color or "#ffffff",
                    "image_url": img_url,
                })
            return result
        if field_name == "bottom_bar_items":
            content = dict(self.bottom_bar_content) if isinstance(self.bottom_bar_content, dict) else {}
            content["messages"] = [
                item.value or item.label
                for item in self.bottom_bar_items
                if (item.value or item.label) and item.is_active
            ]
            return content
        if field_name == "design_settings_id":
            settings = dict(self.design_settings) if isinstance(self.design_settings, dict) else {}
            design = self.design_settings_id[:1]
            if design:
                settings.update(design.get_design_dict())
            settings.setdefault("sidebar_header_type", self.sidebar_header_type or "text")
            settings.setdefault("sidebar_header_value", self.sidebar_header_value or self.name)
            return settings
        return None

    @api.model
    def _youtube_key(self, url):
        """Identificador estable del video (ID de YouTube) a partir de la URL."""
        import re

        if not url:
            return False
        match = re.search(
            r'(?:youtube\.com/(?:[^/]+/.+/|(?:v|e(?:mbed)?|shorts|live)/|.*[?&]v=)|youtu\.be/)'
            r'([^"&?/\s]{11})',
            url,
        )
        return match.group(1) if match else url

    def _cleanup_playlist_duplicates(self):
        """Elimina videos repetidos (misma URL o mismo ID de YouTube)."""
        removed = 0
        Playlist = self.env["vscreens.playlist.item"]
        for company in self:
            seen = set()
            for item in Playlist.search([("company_id", "=", company.id)], order="id"):
                key = item.youtube_id or self._youtube_key(item.url)
                if key in seen:
                    item.unlink()
                    removed += 1
                else:
                    seen.add(key)
        return removed

    def _hydrate_visuals_from_json(self):
        """Completa los controles visuales con la configuración JSON histórica.

        Es idempotente: sólo crea los registros que faltan, comparando por
        URL/texto, de forma que se puede ejecutar varias veces sin duplicar.
        """
        Playlist = self.env["vscreens.playlist.item"]
        Scheduled = self.env["vscreens.scheduled.video.item"]
        Sidebar = self.env["vscreens.sidebar.item"]
        BottomBar = self.env["vscreens.bottom.bar.item"]
        Design = self.env["vscreens.design.settings"]
        created = 0

        for company in self:
            # Playlist
            known = {item.youtube_id or item.url for item in company.playlist_items if item.url}
            sequence = 10
            for entry in (company.video_playlist or []):
                if isinstance(entry, str):
                    url, title = entry, entry
                elif isinstance(entry, dict):
                    url = entry.get("url")
                    title = entry.get("title") or url
                else:
                    continue
                if not url:
                    sequence += 10
                    continue
                key = self._youtube_key(url)
                if key in known:
                    sequence += 10
                    continue
                try:
                    with self.env.cr.savepoint():
                        Playlist.create({
                            "company_id": company.id,
                            "sequence": sequence,
                            "title": title or url,
                            "url": url,
                            "is_active": True,
                        })
                        known.add(key)
                        created += 1
                except Exception:  # noqa: BLE001
                    pass
                sequence += 10

            # Elimina duplicados históricos del mismo video
            company._cleanup_playlist_duplicates()

            # Videos programados
            known_scheduled = {
                (item.url, item.start_datetime) for item in company.scheduled_video_items
            }
            sequence = 10
            for entry in (company.scheduled_videos or []):
                if not isinstance(entry, dict):
                    continue
                url = entry.get("url")
                start = entry.get("start")
                if not url or not start or (url, start) in known_scheduled:
                    sequence += 10
                    continue
                try:
                    with self.env.cr.savepoint():
                        Scheduled.create({
                            "company_id": company.id,
                            "sequence": sequence,
                            "title": entry.get("title") or url,
                            "url": url,
                            "is_active": True,
                            "start_datetime": start,
                            "end_datetime": entry.get("end") or False,
                            "duration": entry.get("duration") or 300,
                        })
                        created += 1
                except Exception:  # noqa: BLE001
                    pass
                sequence += 10

            # Barra lateral
            known_sidebar = {item.value for item in company.sidebar_items}
            sequence = 10
            for entry in (company.sidebar_content or []):
                if not isinstance(entry, dict):
                    continue
                value = entry.get("value") or entry.get("text")
                if not value or value in known_sidebar:
                    sequence += 10
                    continue
                try:
                    with self.env.cr.savepoint():
                        Sidebar.create({
                            "company_id": company.id,
                            "sequence": sequence,
                            "label": entry.get("label") or value[:40],
                            "value": value,
                            "is_active": True,
                            "icon": entry.get("icon") or "fa-tv",
                            "color": entry.get("color") or "#ffffff",
                        })
                        known_sidebar.add(value)
                        created += 1
                except Exception:  # noqa: BLE001
                    pass
                sequence += 10

            # Barra inferior
            bottom_data = company.bottom_bar_content if isinstance(company.bottom_bar_content, dict) else {}
            messages = bottom_data.get("messages") or ([bottom_data.get("static")] if bottom_data.get("static") else [])
            known_bottom = {item.value for item in company.bottom_bar_items}
            sequence = 10
            for message in messages:
                text = message if isinstance(message, str) else str(message)
                if not text.strip() or text in known_bottom:
                    sequence += 10
                    continue
                try:
                    with self.env.cr.savepoint():
                        BottomBar.create({
                            "company_id": company.id,
                            "sequence": sequence,
                            "label": text[:40],
                            "value": text,
                            "is_active": True,
                            "color": bottom_data.get("color") or "#c8ff00",
                        })
                        known_bottom.add(text)
                        created += 1
                except Exception:  # noqa: BLE001
                    pass
                sequence += 10

            # Ajustes de diseño
            if not company.design_settings_id:
                data = company.design_settings if isinstance(company.design_settings, dict) else {}
                try:
                    with self.env.cr.savepoint():
                        Design.create({
                            "company_id": company.id,
                            "title_font": data.get("name_font") or "inherit",
                            "title_color": data.get("name_color") or "#ffffff",
                            "title_size": data.get("name_size") or "1.2rem",
                            "title_weight": data.get("name_weight") or "bold",
                            "sidebar_width": int(data.get("sidebar_width") or 22),
                            "sidebar_effect": data.get("sidebar_effect") or "none",
                            "sidebar_bg": data.get("sidebar_bg") or "#1e293b",
                            "sidebar_text": data.get("sidebar_text") or "#ffffff",
                            "bottom_bar_bg": data.get("bottom_bar_bg") or "#0a0e1a",
                            "bottom_bar_text": data.get("bottom_bar_text") or "#ffffff",
                            "show_bcv": bool(data.get("show_bcv", True)),
                            "bcv_color": data.get("bcv_color") or "#10b981",
                            "bcv_font": data.get("bcv_font") or "inherit",
                        })
                        created += 1
                except Exception:  # noqa: BLE001
                    pass

        return created

    def _normalize_playlist_json(self):
        """Convierte playlists antiguas con objetos a la lista de URLs que usa la TV."""
        normalized = 0
        for company in self:
            values = []
            for entry in company.video_playlist or []:
                if isinstance(entry, str):
                    values.append(entry)
                elif isinstance(entry, dict):
                    url = entry.get("url") or entry.get("youtube_id")
                    if url:
                        values.append(url)
            if values != company.video_playlist:
                super(VScreenSCompany, company).write({"video_playlist": values})
                normalized += 1
        return normalized

    def _sync_visual_to_json(self, field_names):
        """Vuelca sólo los One2many editados a los JSON de configuración."""
        for record in self:
            vals = {}
            for field_name in field_names:
                json_field = self._VISUAL_JSON_MAP.get(field_name)
                if json_field:
                    vals[json_field] = record._dump_visual_field(field_name)
            if vals:
                # super() evita recursión sobre este mismo write().
                super(VScreenSCompany, record).write(vals)

    def _migrate_legacy_socials(self):
        """Pasa WhatsApp/Instagram del JSON viejo a los campos editables de la empresa."""
        migrated = 0
        for company in self:
            content = company.bottom_bar_content if isinstance(company.bottom_bar_content, dict) else {}
            vals = {}
            if not company.whatsapp and content.get("whatsapp"):
                vals["whatsapp"] = content["whatsapp"]
            if not company.instagram and content.get("instagram"):
                vals["instagram"] = content["instagram"]
            if vals:
                company.write(vals)
                migrated += 1
        return migrated

    def _replace_visuals_from_json(self, field_names):
        """Reconstruye los controles visuales cuando el panel web escribe el JSON.

        Así el panel web (API) y Odoo quedan sincronizados en ambos sentidos.
        """
        Playlist = self.env["vscreens.playlist.item"].sudo()
        Scheduled = self.env["vscreens.scheduled.video.item"].sudo()
        Sidebar = self.env["vscreens.sidebar.item"].sudo()
        Bottom = self.env["vscreens.bottom.bar.item"].sudo()
        Design = self.env["vscreens.design.settings"].sudo()

        def safe_create(model, vals):
            try:
                with self.env.cr.savepoint():
                    model.create(vals)
            except Exception:  # noqa: BLE001 - un dato inválido no rompe la sincronización
                pass

        for company in self:
            if "video_playlist" in field_names:
                titles = {item.url: item.title for item in company.playlist_items if item.url}
                company.playlist_items.sudo().unlink()
                sequence = 10
                for entry in company.video_playlist or []:
                    if isinstance(entry, str):
                        url, title = entry, entry
                    elif isinstance(entry, dict):
                        url = entry.get("url") or entry.get("youtube_id")
                        title = entry.get("title") or url
                    else:
                        continue
                    if url:
                        safe_create(Playlist, {
                            "company_id": company.id,
                            "sequence": sequence,
                            "title": title or titles.get(url) or url,
                            "url": url,
                        })
                    sequence += 10

            if "scheduled_videos" in field_names:
                company.scheduled_video_items.sudo().unlink()
                sequence = 10
                for entry in company.scheduled_videos or []:
                    if not isinstance(entry, dict):
                        continue
                    url = entry.get("url")
                    if not url or not entry.get("start"):
                        continue
                    safe_create(Scheduled, {
                        "company_id": company.id,
                        "sequence": sequence,
                        "title": entry.get("title") or url,
                        "url": url,
                        "start_datetime": entry.get("start"),
                        "end_datetime": entry.get("end") or False,
                        "duration": entry.get("duration") or 300,
                    })
                    sequence += 10

            if "sidebar_content" in field_names:
                company.sidebar_items.sudo().unlink()
                sequence = 10
                for entry in company.sidebar_content or []:
                    if not isinstance(entry, dict):
                        continue
                    value = entry.get("value") or entry.get("text")
                    if not value:
                        continue
                    safe_create(Sidebar, {
                        "company_id": company.id,
                        "sequence": sequence,
                        "label": entry.get("label") or value[:40],
                        "value": value,
                        "icon": entry.get("icon") or "fa-tv",
                        "color": entry.get("color") or "#ffffff",
                        "image_url": entry.get("image_url") or entry.get("image") or False,
                    })
                    sequence += 10

            if "bottom_bar_content" in field_names:
                company.bottom_bar_items.sudo().unlink()
                data = company.bottom_bar_content if isinstance(company.bottom_bar_content, dict) else {}
                messages = data.get("messages") or ([data.get("static")] if data.get("static") else [])
                sequence = 10
                for message in messages:
                    text = message if isinstance(message, str) else str(message)
                    if not text.strip():
                        continue
                    safe_create(Bottom, {
                        "company_id": company.id,
                        "sequence": sequence,
                        "label": text[:40],
                        "value": text,
                        "color": data.get("color") or "#c8ff00",
                    })
                    sequence += 10

            if "design_settings" in field_names:
                company.design_settings_id.sudo().unlink()
                data = company.design_settings if isinstance(company.design_settings, dict) else {}
                if data:
                    anim = data.get("sidebar_animation")
                    if anim not in ("slide_up", "fade", "slide_left", "zoom", "none"):
                        anim = "slide_up"
                    fscale = data.get("sidebar_font_scale")
                    if fscale not in ("compact", "normal", "large"):
                        fscale = "normal"
                    effect = data.get("sidebar_effect")
                    if effect not in ("none", "glass_3d", "neon_glow"):
                        effect = "none"
                    safe_create(Design, {
                        "company_id": company.id,
                        "title_font": data.get("name_font") or "inherit",
                        "title_color": data.get("name_color") or "#ffffff",
                        "title_size": data.get("name_size") or "1.2rem",
                        "title_weight": data.get("name_weight") or "bold",
                        "sidebar_width": int(data.get("sidebar_width") or 22),
                        "sidebar_effect": effect,
                        "sidebar_bg": data.get("sidebar_bg") or "#1e293b",
                        "sidebar_text": data.get("sidebar_text") or "#ffffff",
                        "sidebar_animation": anim,
                        "sidebar_font_scale": fscale,
                        "side_subtitle": data.get("side_subtitle") if data.get("side_subtitle") is not None else "PANTALLAS PUBLI-INTELIGENTES",
                        "show_side_footer": bool(data.get("show_side_footer", True)),
                        "side_footer_text": data.get("side_footer_text") if data.get("side_footer_text") is not None else "VScreenS · Señalización inteligente",
                        "show_side_clock": bool(data.get("show_side_clock", False)),
                        "bottom_bar_bg": data.get("bottom_bar_bg") or "#0a0e1a",
                        "bottom_bar_text": data.get("bottom_bar_text") or "#ffffff",
                        "show_bottom_clock": bool(data.get("show_bottom_clock", True)),
                        "show_topbar_date": bool(data.get("show_topbar_date", True)),
                        "show_live_badge": bool(data.get("show_live_badge", True)),
                        "show_social_in_ticker": bool(data.get("show_social_in_ticker", True)),
                        "show_bcv": bool(data.get("show_bcv", True)),
                        "bcv_color": data.get("bcv_color") or "#10b981",
                        "bcv_font": data.get("bcv_font") or "inherit",
                    })

    def _sync_all_visual_to_json(self):
        """Vuelca todos los controles visuales al JSON que consume el panel web."""
        self._sync_visual_to_json(list(self._VISUAL_JSON_MAP))
        return True

    def _notification_settings_dict(self):
        self.ensure_one()
        return {key: bool(self[field]) for field, key in self._NOTIFICATION_FIELDS.items()}

    @api.model_create_multi
    def create(self, vals_list):
        records = super().create(vals_list)
        for record, vals in zip(records, vals_list):
            touched = [f for f in self._VISUAL_JSON_MAP if f in vals]
            if touched:
                record._sync_visual_to_json(touched)
        return records

    _JSON_VISUAL_FIELDS = (
        "video_playlist",
        "scheduled_videos",
        "sidebar_content",
        "bottom_bar_content",
        "design_settings",
    )

    def write(self, vals):
        res = super().write(vals)
        json_touched = [f for f in self._JSON_VISUAL_FIELDS if f in vals]
        if json_touched and not self.env.context.get("vscreens_skip_visual_rebuild"):
            self._replace_visuals_from_json(json_touched)
        touched = [f for f in self._VISUAL_JSON_MAP if f in vals]
        if touched:
            self._sync_visual_to_json(touched)
        if any(field in vals for field in self._NOTIFICATION_FIELDS):
            for record in self:
                super(VScreenSCompany, record).write(
                    {"auto_notification_settings": record._notification_settings_dict()}
                )
        return res

    def _uses_visual_config(self):
        """True si la empresa ya se gestiona con los controles visuales de Odoo."""
        self.ensure_one()
        return bool(
            self.playlist_items
            or self.scheduled_video_items
            or self.sidebar_items
            or self.bottom_bar_items
            or self.design_settings_id
        )

    def _active_scheduled_from_visual(self):
        """Videos programados activos según la ventana de fecha/hora configurada."""
        self.ensure_one()
        now = fields.Datetime.now()
        active = []
        for item in self.scheduled_video_items:
            if not item.is_active or not item.url:
                continue
            if item.start_datetime and now < item.start_datetime:
                continue
            if item.end_datetime and now > item.end_datetime:
                continue
            active.append({
                "url": item.url,
                "title": item.title or "",
                "start": fields.Datetime.to_string(item.start_datetime) if item.start_datetime else False,
                "end": fields.Datetime.to_string(item.end_datetime) if item.end_datetime else False,
                "duration": item.duration or 300,
                "scheduled": True,
            })
        return active

    def _logo_url(self):
        """URL pública del logo: la configurada o el archivo subido en Odoo."""
        self.ensure_one()
        if self.logo_url:
            return self.logo_url
        if not self.logo:
            return False
        base = self.env["ir.config_parameter"].sudo().get_str("web.base.url", "").rstrip("/")
        if not base or "127.0.0.1" in base or "localhost" in base:
            base = "https://vscreens-api.inverpave.com"
        stamp = int(self.write_date.timestamp()) if self.write_date else 0
        return f"{base}/web/image/vscreens.company/{self.id}/logo?unique={stamp}"

    def _merged_bottom_bar(self, extra=None):
        """Barra inferior con los mensajes y las redes configuradas en Odoo."""
        self.ensure_one()
        content = dict(self.bottom_bar_content) if isinstance(self.bottom_bar_content, dict) else {}
        if isinstance(extra, dict):
            content.update(extra)
        # Las redes salen únicamente de los campos de la empresa, nunca del JSON viejo.
        for key in ("whatsapp", "instagram", "facebook", "tiktok", "phone"):
            content.pop(key, None)
        if self.whatsapp:
            content["whatsapp"] = self.whatsapp
        if self.instagram:
            content["instagram"] = self.instagram.lstrip("@")
        if self.facebook:
            content["facebook"] = self.facebook
        if self.tiktok:
            content["tiktok"] = self.tiktok.lstrip("@")
        return content

    # ------------------------------------------------------------------
    # Enlace configurable con el Odoo del cliente
    # ------------------------------------------------------------------
    def action_send_welcome_email(self, login=None, password=None):
        """Correo de alta: código Downloader (AFTVnews), enlace directo, panel y credenciales."""
        self.ensure_one()
        Code = self.env["vscreens.download.code"].sudo()
        apps = self.env["product.template"].sudo().search([
            ("is_digital", "=", True),
            ("digital_file", "!=", False),
        ])
        codes = []
        for product in apps:
            record = Code.generate(
                product=product,
                company=self,
                partner=self.partner_id,
                notes="Alta / prueba gratuita",
            )
            if record:
                aftv_code = (record.aftvnews_code or product.aftvnews_code or "").strip()
                codes.append((product.name, record.code, aftv_code))

        users = self.user_ids.filtered(
            lambda user: not user.has_group("vscreens.group_vscreens_master")
        )
        user_login = login or (users[:1].login if users else (self.email or ""))
        user_password = password or (
            "la contraseña que elegiste al registrarte"
            if user_login
            else "la que te proporcione el administrador"
        )
        panel = "https://vscreens-app.inverpave.com"
        rows = "".join(
            f"<tr>"
            f"<td style='padding:8px 12px;border:1px solid #e5e7eb;'><b>{product}</b></td>"
            f"<td style='padding:8px 12px;border:1px solid #e5e7eb;font-family:monospace;"
            f"font-size:20px;font-weight:bold;letter-spacing:3px;color:#166534;'>"
            f"{aftv_code if aftv_code else '—'}</td>"
            f"<td style='padding:8px 12px;border:1px solid #e5e7eb;font-family:monospace;font-size:13px;'>"
            f"https://vscreens.inverpave.com/d/{code}</td>"
            f"</tr>"
            for product, code, aftv_code in codes
        )
        body = f"""
        <div style="font-family:Arial,sans-serif;color:#1f2937;max-width:640px;margin:auto;">
          <div style="background:#0a0e1a;color:#fff;border-radius:14px;padding:22px;">
            <div style="color:#c8ff00;font-weight:bold;letter-spacing:2px;">VSCREENS</div>
            <div style="font-size:22px;font-weight:bold;margin-top:6px;">Bienvenido a VScreenS</div>
          </div>
          <div style="padding:18px 4px;line-height:1.7;font-size:14px;">
            <p>Hola {self.name}, tu cuenta está lista. Sigue estos pasos para poner tu pantalla en línea.</p>
            <h3>1. Descarga la app en tu TV</h3>
            <p>Instala <b>Downloader (by AFTVnews)</b> desde la tienda de tu Android TV / Fire TV:</p>
            <ul>
              <li><b>Con código numérico AFTVnews (recomendado):</b> escribe el código numérico de la columna <em>Código Downloader</em> y pulsa <b>Go</b>.</li>
              <li><b>Con enlace directo:</b> escribe la URL completa de la columna <em>Enlace directo</em> (incluyendo <code>https://</code>) y pulsa <b>Go</b>.</li>
            </ul>
            <table style="border-collapse:collapse;margin:10px 0;width:100%;">
              <thead>
                <tr style="background:#f3f4f6;">
                  <th style="padding:8px 12px;border:1px solid #e5e7eb;text-align:left;">Aplicación</th>
                  <th style="padding:8px 12px;border:1px solid #e5e7eb;text-align:left;">Código Downloader (AFTVnews)</th>
                  <th style="padding:8px 12px;border:1px solid #e5e7eb;text-align:left;">Enlace directo (URL)</th>
                </tr>
              </thead>
              <tbody>{rows}</tbody>
            </table>
            <h3>2. Registra tu pantalla</h3>
            <p>Descarga e instala el APK. Al abrirlo, genera el código de vinculación desde el panel
            y registra la pantalla. Sin este paso la app <b>no mostrará contenido</b>.</p>
            <h3>3. Entra al panel</h3>
            <p><a href="{panel}">{panel}</a></p>
            <p>Usuario: <b>{user_login}</b><br/>Contraseña: <b>{user_password}</b></p>
            <p style="font-size:12px;color:#6b7280;">
              Soporte: 0414-5694075 · info.vscreens@inverpave.com
            </p>
          </div>
        </div>
        """
        mail = self.env["mail.mail"].sudo().create({
            "subject": f"VScreenS — Instrucciones y código de descarga para {self.name}",
            "email_to": self.email or (self.partner_id.email if self.partner_id else False),
            "body_html": body,
            "model": "vscreens.company",
            "res_id": self.id,
        })
        mail.send()
        return True

    def _odoo_link_session(self):
        """Autentica contra el Odoo del cliente. Devuelve (session, base, error)."""
        self.ensure_one()
        base = (self.odoo_link_url or "").strip().rstrip("/")
        if not base or not base.startswith("https://"):
            return None, base, "La URL debe usar https://"
        if not all((self.odoo_link_db, self.odoo_link_user, self.odoo_link_password)):
            return None, base, "Faltan base de datos, usuario o contraseña"
        session = requests.Session()
        try:
            response = session.post(
                f"{base}/web/session/authenticate",
                json={
                    "jsonrpc": "2.0",
                    "params": {
                        "db": self.odoo_link_db,
                        "login": self.odoo_link_user,
                        "password": self.odoo_link_password,
                    },
                },
                timeout=10,
                headers={"User-Agent": "VScreenS-OdooLink/1.0"},
            )
            data = response.json()
            if data.get("error") or not (data.get("result") or {}).get("uid"):
                return None, base, "Credenciales o base de datos incorrectas"
        except Exception as error:  # noqa: BLE001
            return None, base, f"No se pudo conectar: {str(error)[:120]}"
        return session, base, False

    def action_test_odoo_link(self):
        self.ensure_one()
        session, base, error = self._odoo_link_session()
        message = error or f"Conexión correcta con {base}"
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": "Enlace Odoo",
                "message": message,
                "type": "success" if not error else "warning",
            },
        }

    def _sync_odoo_link(self):
        self.ensure_one()
        if not self.odoo_link_enabled:
            return False
        session, base, error = self._odoo_link_session()
        if error:
            self.write({"odoo_link_error": error})
            return False

        try:
            domain = ast.literal_eval(self.odoo_link_domain or "[]")
            if not isinstance(domain, list):
                domain = []
        except (ValueError, SyntaxError):
            domain = []

        fields_list = ["id"]
        labels = []
        for item in (self.odoo_link_fields or "").split(","):
            if ":" not in item:
                continue
            field_name, label = item.split(":", 1)
            import re

            field_name = field_name.strip()
            if re.fullmatch(r"[a-z_][a-z0-9_]*", field_name):
                labels.append((label.strip() or field_name, field_name))
                if field_name not in fields_list:
                    fields_list.append(field_name)

        try:
            response = session.post(
                f"{base}/web/dataset/call_kw/{self.odoo_link_model}/search_read",
                json={
                    "jsonrpc": "2.0",
                    "params": {
                        "model": self.odoo_link_model,
                        "method": "search_read",
                        "args": [domain],
                        "kwargs": {
                            "fields": fields_list,
                            "limit": min(max(self.odoo_link_limit or 5, 1), 20),
                            "order": "id desc",
                        },
                    },
                },
                timeout=15,
            )
            result = response.json()
            if result.get("error"):
                raise ValueError(str(result["error"])[:120])
            rows = result.get("result") or []
        except Exception as error:  # noqa: BLE001
            self.write({"odoo_link_error": f"Error al consultar: {str(error)[:120]}"})
            return False

        records = []
        for row in rows:
            values = []
            for label, field_name in labels:
                value = row.get(field_name)
                if isinstance(value, list) and len(value) == 2:
                    value = value[1]
                if isinstance(value, (dict, list)):
                    continue
                if value is None or value is False:
                    value = ""
                values.append({"label": label, "value": str(value)[:80]})
            records.append({
                "id": row.get("id"),
                "title": str(row.get("name") or row.get("id") or "")[:80],
                "values": values,
                "url": f"{base}/odoo/{self.odoo_link_model}/{row.get('id')}",
            })

        self.write({
            "odoo_link_data": records,
            "odoo_link_error": False,
            "odoo_link_last_sync": fields.Datetime.now(),
        })
        return True

    @api.model
    def cron_sync_odoo_links(self):
        now = fields.Datetime.now()
        companies = self.sudo().search([("odoo_link_enabled", "=", True)])
        synced = 0
        for company in companies:
            minutes = max(company.odoo_link_refresh or 60, 5)
            if company.odoo_link_last_sync and (
                now - company.odoo_link_last_sync
            ).total_seconds() < minutes * 60:
                continue
            try:
                with self.env.cr.savepoint():
                    if company._sync_odoo_link():
                        synced += 1
            except Exception as error:  # noqa: BLE001
                _logger.warning("VScreenS Odoo link falló en empresa %s: %s", company.id, error)
        return synced

    def _odoo_widget_config(self):
        self.ensure_one()
        if not self.odoo_link_enabled:
            return {}
        return {
            "enabled": True,
            "label": self.odoo_link_label or "Odoo",
            "icon": self.odoo_link_icon or "fa-file-text",
            "color": self.odoo_link_color or "#c8ff00",
            "records": self.odoo_link_data or [],
            "error": self.odoo_link_error or False,
            "last_sync": self._iso(self.odoo_link_last_sync),
        }

    def _base_config(self):
        self.ensure_one()
        alert = self._get_active_alert()
        menus = self._get_menus()
        visual = self._uses_visual_config()
        from .vscreens_currency import get_bcv_rate

        config = {
            "is_active": True,
            "name": self.name,
            "layout_type": self.layout_type,
            "active_alert": {
                "id": alert.id,
                "subject": alert.subject,
                "body": alert.body,
                "duration": alert.alert_duration or 15,
            } if alert else None,
            "primary_color": self.primary_color,
            "secondary_color": self.secondary_color,
            "accent_color": self.accent_color,
            "logo_url": self._logo_url(),
            "filler_keywords": self.filler_keywords,
            "google_drive_link": self.google_drive_link,
            "video_source": self.video_source,
            "priority_content_url": self.priority_content_url,
            "video_playlist": (
                self._dump_visual_field("playlist_items")
                if visual else (self.video_playlist or [])
            ),
            "scheduled_videos": (
                self._active_scheduled_from_visual()
                if visual else self._active_scheduled_videos()
            ),
            "sidebar_content": (
                self._dump_visual_field("sidebar_items")
                if visual else (self.sidebar_content or [])
            ),
            "bottom_bar_content": self._merged_bottom_bar(
                self._dump_visual_field("bottom_bar_items") if visual else None
            ),
            "design_settings": (
                self._dump_visual_field("design_settings_id")
                if visual else (self.design_settings or {})
            ),
            "pause_duration": self.pause_duration,
            "ad_frequency": self.ad_frequency,
            "bcv_rate": get_bcv_rate(self.env),
            "plan": self.plan_code or "free",
            "sidebar_header_type": self.sidebar_header_type,
            "sidebar_header_value": self.sidebar_header_value or self.name,
            "phone": self.phone,
            "whatsapp": self.whatsapp,
            "instagram": self.instagram,
            "facebook": self.facebook,
            "tiktok": self.tiktok,
            "address": self.address,
            "menus": [
                {"name": item.name, "price": item.price, "category": item.category}
                for item in menus
            ],
            "ping_command": False,
            "config_version": self.config_version or 1,
            "allow_youtube_control": bool(self.allow_tv_youtube_control),
            "youtube_control_minutes": self.tv_youtube_control_minutes or 30,
            "notification_settings": self._notification_settings_dict(),
            "odoo_widget": self._odoo_widget_config(),
            "last_updated": self._iso(self.write_date or self.create_date),
        }
        config = self._apply_plan_locks(config)
        config = self._free_plan_overrides(config)
        # Hash determinista para que las TVs detecten cambios en alertas, BCV, menús,
        # videos programados o anuncios globales aunque write_date de empresa no cambie.
        sig_payload = json.dumps(config, sort_keys=True, default=str).encode("utf-8")
        config["config_hash"] = hashlib.sha256(sig_payload).hexdigest()[:16]
        config["last_updated"] = f"{config['last_updated'] or ''}:{config['config_hash']}"
        return config

    def device_config(self, device):
        self.ensure_one()
        if not device.is_active:
            return {
                "is_active": False,
                "error": "Dispositivo Suspendido por Administración",
                "name": "Dispositivo Inactivo",
            }
        if not self._is_service_active():
            return {
                "is_active": False,
                "name": self.name,
                "layout_type": self.layout_type,
                "primary_color": self.primary_color,
                "secondary_color": self.secondary_color,
                "accent_color": self.accent_color,
            }
        if not self._is_plan_unlimited() and len(self.device_ids) > self.max_screens_effective:
            return {
                "is_active": False,
                "name": self.name,
                "error": f"Límite de pantallas excedido ({self.max_screens_effective}). Por favor actualice su plan.",
            }
        config = self._base_config()
        if device.ping_requested_at:
            delta = fields.Datetime.now() - device.ping_requested_at
            if delta.total_seconds() < 15:
                config["ping_command"] = True
        return config

    def preview_config(self):
        self.ensure_one()
        from ..controllers.api_common import make_preview_token
        cfg = self._base_config()
        cfg["tv_url"] = self.env["ir.config_parameter"].sudo().get_str(
            "vscreens.tv_url", "https://vscreens-tv.inverpave.com"
        ).rstrip("/")
        cfg["preview_token"] = make_preview_token(self.id)
        return cfg

    @api.model
    def preview_config_draft(self, company_id, draft=None):
        """Configuración para la vista previa en vivo con los cambios sin guardar.

        El panel de previsualización envía los valores que el usuario tiene en
        pantalla; aquí se fusionan con la configuración guardada para que la TV
        muestre exactamente lo que se está editando.
        """
        company = self.browse(company_id).exists()
        if not company:
            return {}
        config = company._base_config()
        if isinstance(draft, dict):
            if "odoo_link_enabled" in draft:
                widget = dict(config.get("odoo_widget") or {})
                if not draft.get("odoo_link_enabled"):
                    widget = {}
                else:
                    for key, source in (
                        ("label", "odoo_link_label"),
                        ("icon", "odoo_link_icon"),
                        ("color", "odoo_link_color"),
                    ):
                        if source in draft:
                            widget[key] = draft[source]
                config["odoo_widget"] = widget
            socials = {
                key: draft[key]
                for key in ("whatsapp", "instagram", "phone")
                if draft.get(key)
            }
            if socials:
                base_bottom = draft.get("bottom_bar_content")
                base_bottom = dict(base_bottom) if isinstance(base_bottom, dict) else dict(config.get("bottom_bar_content") or {})
                base_bottom.update(socials)
                draft = dict(draft, bottom_bar_content=base_bottom)
            for key in (
                "name",
                "layout_type",
                "primary_color",
                "secondary_color",
                "accent_color",
                "logo_url",
                "video_source",
                "filler_keywords",
                "google_drive_link",
                "priority_content_url",
                "pause_duration",
                "ad_frequency",
                "address",
                "allow_youtube_control",
                "youtube_control_minutes",
                "odoo_link_enabled",
                "odoo_link_label",
                "odoo_link_icon",
                "odoo_link_color",
                "odoo_widget",
                "sidebar_header_type",
                "sidebar_header_value",
                "phone",
                "whatsapp",
                "instagram",
                "facebook",
                "tiktok",
                "video_playlist",
                "scheduled_videos",
                "sidebar_content",
                "bottom_bar_content",
                "design_settings",
            ):
                if key in draft:
                    config[key] = draft[key]
        return company._apply_plan_locks(config)

    def api_dict(self, full=True):
        self.ensure_one()
        base = {
            "id": self.id,
            "name": self.name,
            "plan": self.plan_code or "free",
            "is_active": self.is_active,
            "max_screens": self.max_screens_effective,
            "active_screens": self.active_screens,
            "total_screens": self.total_screens,
            "valid_until": self._iso(self.valid_until),
            "logo_url": self.logo_url,
            "primary_color": self.primary_color,
            "secondary_color": self.secondary_color,
            "accent_color": self.accent_color,
        }
        if not full:
            return base
        base.update({
            "layout_type": self.layout_type,
            "filler_keywords": self.filler_keywords,
            "google_drive_link": self.google_drive_link,
            "video_source": self.video_source,
            "priority_content_url": self.priority_content_url,
            "video_playlist": self.video_playlist or [],
            "scheduled_videos": self._active_scheduled_videos(),
            "sidebar_content": self.sidebar_content or [],
            "bottom_bar_content": self.bottom_bar_content or {},
            "design_settings": self.design_settings or {},
            "pause_duration": self.pause_duration,
            "ad_frequency": self.ad_frequency,
            "sidebar_header_type": self.sidebar_header_type,
            "sidebar_header_value": self.sidebar_header_value,
            "rif": self.rif,
            "address": self.address,
            "phone": self.phone,
            "whatsapp": self.whatsapp,
            "instagram": self.instagram,
            "facebook": self.facebook,
            "tiktok": self.tiktok,
            "contact_person": self.contact_person,
            "email": self.email,
            "client_editable_fields": self.client_editable_fields,
            "can_edit_profile": self.can_edit_profile,
            "has_edited_profile": self.has_edited_profile,
            "plan_activated_at": self._iso(self.plan_activated_at),
            "first_screen_connected_at": self._iso(self.first_screen_connected_at),
            "total_screens": self.total_screens,
            "active_screens": self.active_screens,
            "plan_features": {
                "allow_third_party_ads": self._plan_allows("allow_third_party_ads"),
                "allow_custom_branding": self._plan_allows("allow_custom_branding"),
                "allow_sidebar": self._plan_allows("allow_sidebar"),
                "allow_bottom_bar": self._plan_allows("allow_bottom_bar"),
                "allow_video_playlist": self._plan_allows("allow_video_playlist"),
                "allow_priority_content": self._plan_allows("allow_priority_content"),
                "allow_bcv": self._plan_allows("allow_bcv"),
                "allow_multi_user": self._plan_allows("allow_multi_user"),
                "allow_helpdesk": self._plan_allows("allow_helpdesk"),
                "allow_mobile": self._plan_allows("allow_mobile"),
                "allow_api": self._plan_allows("allow_api"),
                "max_screens": self.max_screens_effective,
                "max_users": self.plan_id.max_users if self.plan_id else 1,
                "trial_days": self.plan_id.trial_days if self.plan_id else 0,
            },
        })
        return base

    def action_generate_registration_code(self):
        self.ensure_one()
        result = self.env["vscreens.registration.code"].generate_for_company(self)
        code = result.get("code", "")
        mins = result.get("expires_in_minutes", 10)
        self.message_post(
            body=f"Código de vinculación TV generado: {code} (válido por {mins} minutos)."
        )
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": f"Código de Vinculación: {code}",
                "message": f"Ingresa el código {code} en tu TV. Válido por {mins} minutos.",
                "type": "success",
                "sticky": True,
            },
        }

    def action_view_devices(self):
        self.ensure_one()
        return {
            "type": "ir.actions.act_window",
            "name": "Pantallas",
            "res_model": "vscreens.device",
            "view_mode": "list,form",
            "domain": [("company_id", "=", self.id)],
            "context": {"default_company_id": self.id},
        }

    def action_view_users(self):
        self.ensure_one()
        return {
            "type": "ir.actions.act_window",
            "name": "Usuarios",
            "res_model": "res.users",
            "view_mode": "list,form",
            "domain": [("vscreens_company_id", "=", self.id)],
            "context": {"default_vscreens_company_id": self.id},
        }

    def action_view_payments(self):
        self.ensure_one()
        return {
            "type": "ir.actions.act_window",
            "name": "Pagos",
            "res_model": "vscreens.payment",
            "view_mode": "list,form",
            "domain": [("company_id", "=", self.id)],
            "context": {"default_company_id": self.id},
        }

    def action_view_tickets(self):
        self.ensure_one()
        return {
            "type": "ir.actions.act_window",
            "name": "Tickets",
            "res_model": "vscreens.ticket",
            "view_mode": "list,form",
            "domain": [("company_id", "=", self.id)],
            "context": {"default_company_id": self.id},
        }

    def action_preview_tv(self):
        self.ensure_one()
        from ..controllers.api_common import make_preview_token
        base = self.env["ir.config_parameter"].sudo().get_str(
            "vscreens.tv_url", "https://vscreens-tv.inverpave.com"
        ).rstrip("/")
        pt = make_preview_token(self.id)
        return {
            "type": "ir.actions.act_url",
            "url": f"{base}/?preview={self.id}&pt={pt}",
            "target": "new",
        }

    def action_push_config(self, device_ids=None):
        """Publica la configuración actual en las pantallas seleccionadas.

        Si no se seleccionó ninguna pantalla se envía a todas las de la empresa.
        Las pantallas consultan su configuración cada 10 s y aplican la versión
        nueva sin necesidad de reiniciarse (y sin mostrar el banner de ping).
        """
        self.ensure_one()
        if device_ids:
            devices = self.env["vscreens.device"].browse(device_ids).filtered(
                lambda device: device.company_id == self
            )
        else:
            devices = self.push_device_ids or self.device_ids
        super(VScreenSCompany, self).write({"config_version": (self.config_version or 1) + 1})
        self.message_post(
            body=(
                f"Configuración publicada en {len(devices)} pantalla(s). "
                f"Versión {self.config_version}."
            )
        )
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": "Configuración enviada",
                "message": (
                    f"Se envió la configuración a {len(devices)} pantalla(s)."
                    if devices
                    else "La empresa no tiene pantallas registradas todavía."
                ),
                "type": "success" if devices else "warning",
                "sticky": False,
            },
        }

