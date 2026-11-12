from datetime import timedelta

from odoo import api, fields, models
from odoo.exceptions import ValidationError


class VenridesCompany(models.Model):
    _name = "venrides.company"
    _description = "Empresa / cliente VenridesScreenS"
    _inherit = ["mail.thread", "mail.activity.mixin"]
    _order = "name"
    _rec_name = "name"

    name = fields.Char(string="Nombre comercial", required=True, tracking=True)
    partner_id = fields.Many2one("res.partner", string="Contacto / facturación", ondelete="set null")
    plan_id = fields.Many2one("venrides.plan", string="Plan", required=True, tracking=True)
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
    sidebar_content = fields.Json(string="Contenido de barra lateral", default=list)
    bottom_bar_content = fields.Json(string="Contenido de barra inferior", default=dict)
    design_settings = fields.Json(string="Ajustes de diseño", default=dict)
    pause_duration = fields.Integer(string="Duración de pausa (min)", default=10)
    ad_frequency = fields.Integer(string="Frecuencia de anuncios (s)", default=30)
    sidebar_header_type = fields.Selection(
        [("text", "Texto"), ("banner", "Banner")], default="text", string="Tipo de encabezado"
    )
    sidebar_header_value = fields.Char(string="Valor del encabezado")

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

    user_ids = fields.One2many("res.users", "venrides_company_id", string="Usuarios")
    device_ids = fields.One2many("venrides.device", "company_id", string="Pantallas")
    payment_ids = fields.One2many("venrides.payment", "company_id", string="Pagos")
    menu_item_ids = fields.One2many("venrides.menu.item", "company_id", string="Menú")
    message_ids = fields.One2many("venrides.message", "company_id", string="Mensajes")
    ticket_ids = fields.One2many("venrides.ticket", "company_id", string="Tickets")

    total_screens = fields.Integer(string="Pantallas totales", compute="_compute_screen_counts")
    active_screens = fields.Integer(string="Pantallas activas", compute="_compute_screen_counts")
    max_screens_effective = fields.Integer(string="Límite efectivo", compute="_compute_max_screens")

    @api.depends("device_ids", "device_ids.is_active")
    def _compute_screen_counts(self):
        for company in self:
            company.total_screens = len(company.device_ids)
            company.active_screens = len(company.device_ids.filtered("is_active"))

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
        return self.env["venrides.global.ad"].sudo().search([("active", "=", True)], order="write_date desc", limit=1)

    def _get_active_alert(self):
        self.ensure_one()
        return self.env["venrides.message"].sudo().search(
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
            config["bottom_bar_content"] = {"static": "Venrides Pantallas Inteligentes"}
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
                alert_msg = f"⚠️ Tu prueba gratuita vence en {days} días. ¡Suscríbete en venrides.inverpave.com!"
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

    def _base_config(self):
        self.ensure_one()
        alert = self._get_active_alert()
        menus = self._get_menus()
        from .venrides_currency import get_bcv_rate

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
            "last_updated": self._iso(self.write_date or self.create_date),
        }
        return self._free_plan_overrides(config)

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
        })
        return base

    def action_generate_registration_code(self):
        self.ensure_one()
        return self.env["venrides.registration.code"].generate_for_company(self)

    def action_view_devices(self):
        self.ensure_one()
        return {
            "type": "ir.actions.act_window",
            "name": "Pantallas",
            "res_model": "venrides.device",
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
            "domain": [("venrides_company_id", "=", self.id)],
            "context": {"default_venrides_company_id": self.id},
        }

    def action_view_payments(self):
        self.ensure_one()
        return {
            "type": "ir.actions.act_window",
            "name": "Pagos",
            "res_model": "venrides.payment",
            "view_mode": "list,form",
            "domain": [("company_id", "=", self.id)],
            "context": {"default_company_id": self.id},
        }

    def action_view_tickets(self):
        self.ensure_one()
        return {
            "type": "ir.actions.act_window",
            "name": "Tickets",
            "res_model": "venrides.ticket",
            "view_mode": "list,form",
            "domain": [("company_id", "=", self.id)],
            "context": {"default_company_id": self.id},
        }

    def action_preview_tv(self):
        self.ensure_one()
        base = self.env["ir.config_parameter"].sudo().get_param(
            "venrides.tv_url", "https://venrides-tv.inverpave.com"
        )
        return {
            "type": "ir.actions.act_url",
            "url": f"{base}?preview={self.id}",
            "target": "new",
        }

