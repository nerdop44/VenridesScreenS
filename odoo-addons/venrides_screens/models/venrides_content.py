from odoo import fields, models


class VenridesGlobalAd(models.Model):
    _name = "venrides.global.ad"
    _description = "Publicidad global para planes free"
    _order = "write_date desc, id desc"

    name = fields.Char(default="Publicidad global")
    active = fields.Boolean(default=True)
    video_url = fields.Char(string="Video (obsoleto)")
    video_playlist = fields.Json(string="Playlist de videos", default=list)
    ticker_text = fields.Char(string="Ticker (obsoleto)")
    ticker_messages = fields.Json(string="Mensajes del ticker", default=list)
    ad_scripts = fields.Json(string="Scripts de anuncios", default=list)

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "video_url": self.video_url or "",
            "video_playlist": self.video_playlist or [],
            "ticker_text": self.ticker_text or "",
            "ticker_messages": self.ticker_messages or [],
            "ad_scripts": self.ad_scripts or [],
            "updated_at": fields.Datetime.to_string(self.write_date) if self.write_date else None,
        }


class VenridesMenuItem(models.Model):
    _name = "venrides.menu.item"
    _description = "Ítem de menú del cliente"
    _order = "category, name"

    company_id = fields.Many2one("venrides.company", string="Empresa", required=True, ondelete="cascade", index=True)
    name = fields.Char(string="Nombre", required=True)
    price = fields.Float(string="Precio", default=0.0)
    category = fields.Char(string="Categoría")
    is_available = fields.Boolean(string="Disponible", default=True)

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "company_id": self.company_id.id,
            "name": self.name,
            "price": self.price,
            "category": self.category or "",
            "is_available": self.is_available,
        }


class VenridesEmailTemplate(models.Model):
    _name = "venrides.email.template"
    _description = "Plantilla de email VenridesScreenS"
    _order = "category, name"

    name = fields.Char(string="Clave", required=True, index=True)
    subject = fields.Char(string="Asunto", required=True)
    body = fields.Html(string="Cuerpo", required=True)
    default_subject = fields.Char(string="Asunto original")
    default_body = fields.Html(string="Cuerpo original")
    is_system = fields.Boolean(string="Plantilla del sistema", default=False)
    category = fields.Char(string="Categoría", default="general")
    active = fields.Boolean(default=True)

    _sql_constraints = [
        ("name_uniq", "unique(name)", "La clave de la plantilla debe ser única."),
    ]

    def render_for_company(self, company, extra=None):
        self.ensure_one()
        values = {
            "nombre_empresa": company.name or "",
            "contacto": company.contact_person or company.name or "",
            "email": company.email or "",
            "telefono": company.phone or "",
            "plan": (company.plan_code or "free").capitalize(),
            "fecha_vencimiento": fields.Date.to_string(company.valid_until.date()) if company.valid_until else "N/A",
            "pantallas_activas": str(company.active_screens),
            "max_pantallas": str(company.max_screens_effective),
            "fecha_hoy": fields.Date.to_string(fields.Date.today()),
            "whatsapp": company.whatsapp or "",
        }
        values.update(extra or {})
        subject = self.subject or ""
        body = self.body or ""
        for key, value in values.items():
            token = "{{" + key + "}}"
            subject = subject.replace(token, str(value))
            body = body.replace(token, str(value))
        return {"subject": subject, "body": body}


class VenridesPromotion(models.Model):
    _name = "venrides.promotion"
    _description = "Promoción comercial"
    _order = "create_date desc"

    name = fields.Char(required=True)
    description = fields.Text()
    code = fields.Char(required=True, index=True)
    discount_pct = fields.Float(string="Descuento (%)", default=0.0)
    valid_from = fields.Datetime()
    valid_to = fields.Datetime()
    is_active = fields.Boolean(default=True)

    _sql_constraints = [("code_uniq", "unique(code)", "El código de promoción debe ser único.")]

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description or "",
            "code": self.code,
            "discount_pct": self.discount_pct,
            "valid_from": fields.Datetime.to_string(self.valid_from) if self.valid_from else None,
            "valid_to": fields.Datetime.to_string(self.valid_to) if self.valid_to else None,
            "is_active": self.is_active,
        }


class VenridesAffiliate(models.Model):
    _name = "venrides.affiliate"
    _description = "Afiliado comercial"
    _order = "create_date desc"

    name = fields.Char(required=True)
    email = fields.Char(required=True, index=True)
    code = fields.Char(required=True, index=True)
    commission_pct = fields.Float(string="Comisión (%)", default=10.0)
    total_referred = fields.Integer(default=0)
    total_earned = fields.Float(default=0.0)
    is_active = fields.Boolean(default=True)

    _sql_constraints = [
        ("email_uniq", "unique(email)", "El email del afiliado debe ser único."),
        ("code_uniq", "unique(code)", "El código del afiliado debe ser único."),
    ]

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "code": self.code,
            "commission_pct": self.commission_pct,
            "total_referred": self.total_referred,
            "total_earned": self.total_earned,
            "is_active": self.is_active,
        }


class VenridesCalendarActivity(models.Model):
    _name = "venrides.calendar.activity"
    _description = "Actividad o feriado para CRM"
    _order = "activity_date"

    title = fields.Char(required=True)
    description = fields.Text()
    activity_date = fields.Date(required=True)
    is_holiday = fields.Boolean(default=False)
    send_auto_greeting = fields.Boolean(default=False)
    greeting_template_id = fields.Many2one("venrides.email.template", string="Plantilla de saludo")

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description or "",
            "activity_date": fields.Date.to_string(self.activity_date) if self.activity_date else None,
            "is_holiday": self.is_holiday,
            "send_auto_greeting": self.send_auto_greeting,
        }
