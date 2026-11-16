from datetime import timedelta
import json
import logging

from odoo import api, fields, models
from odoo.exceptions import ValidationError


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
        gad = self._get_global_ad()
        if not gad:
            config["bottom_bar_content"] = {"static": "VScreenS Pantallas Inteligentes"}
            return config

        playlist = [v for v in (gad.video_playlist or []) if v and str(v).strip()]
        if not playlist and gad.video_url:
            playlist = [gad.video_url]
        if playlist:
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
            return [
                {
                    "url": item.url,
                    "title": item.title or "",
                    "youtube_id": item.youtube_id or False,
                }
                for item in self.playlist_items
                if item.is_active and item.url
            ]
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
                if item.is_active and item.url
            ]
        if field_name == "sidebar_items":
            return [
                {
                    "type": "text",
                    "label": item.label or "",
                    "value": item.value or item.label or "",
                    "icon": item.icon or False,
                    "color": item.color or "#ffffff",
                }
                for item in self.sidebar_items
                if item.is_active and (item.value or item.label)
            ]
        if field_name == "bottom_bar_items":
            content = dict(self.bottom_bar_content) if isinstance(self.bottom_bar_content, dict) else {}
            content["messages"] = [
                item.value or item.label
                for item in self.bottom_bar_items
                if item.is_active and (item.value or item.label)
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

    def write(self, vals):
        res = super().write(vals)
        touched = [f for f in self._VISUAL_JSON_MAP if f in vals]
        if touched:
            self._sync_visual_to_json(touched)
        if any(field in vals for field in self._NOTIFICATION_FIELDS):
            for record in self:
                super(VScreenSCompany, record).write(
                    {"auto_notification_settings": record._notification_settings_dict()}
                )
        return res

    def _base_config(self):
        self.ensure_one()
        alert = self._get_active_alert()
        menus = self._get_menus()
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
            "logo_url": self.logo_url,
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
            "bcv_rate": get_bcv_rate(self.env),
            "plan": self.plan_code or "free",
            "sidebar_header_type": self.sidebar_header_type,
            "sidebar_header_value": self.sidebar_header_value or self.name,
            "menus": [
                {"name": item.name, "price": item.price, "category": item.category}
                for item in menus
            ],
            "ping_command": False,
            "config_version": self.config_version or 1,
            "notification_settings": self._notification_settings_dict(),
            "last_updated": self._iso(self.write_date or self.create_date),
        }
        config = self._free_plan_overrides(config)
        return self._apply_plan_locks(config)

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
        return self._base_config()

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
                "sidebar_header_type",
                "sidebar_header_value",
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
        return self.env["vscreens.registration.code"].generate_for_company(self)

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
        base = self.env["ir.config_parameter"].sudo().get_str(
            "vscreens.tv_url", "https://vscreens-tv.inverpave.com"
        )
        return {
            "type": "ir.actions.act_url",
            "url": f"{base}?preview={self.id}",
            "target": "new",
        }

    def action_push_config(self, device_ids=None):
        """Publica la configuración actual en las pantallas seleccionadas.

        Si no se seleccionó ninguna pantalla se envía a todas las de la empresa.
        Las pantallas consultan su configuración cada 30 s y aplican la versión
        nueva sin necesidad de reiniciarse.
        """
        self.ensure_one()
        if device_ids:
            devices = self.env["vscreens.device"].browse(device_ids).filtered(
                lambda device: device.company_id == self
            )
        else:
            devices = self.push_device_ids or self.device_ids
        now = fields.Datetime.now()
        if devices:
            devices.sudo().write({"ping_requested_at": now})
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

