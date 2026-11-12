from odoo import fields, models


class VenridesAnalyticsVisit(models.Model):
    _name = "venrides.analytics.visit"
    _description = "Visita analítica del sitio"
    _order = "visit_date desc, id desc"

    page = fields.Char(default="/", index=True)
    referrer = fields.Char()
    device = fields.Char()
    country = fields.Char(default="unknown")
    ip_hash = fields.Char(index=True)
    user_agent = fields.Text()
    visit_date = fields.Datetime(default=fields.Datetime.now, index=True)

    def api_dict(self):
        self.ensure_one()
        return {
            "page": self.page,
            "referrer": self.referrer or "",
            "device": self.device or "",
            "country": self.country or "",
            "timestamp": fields.Datetime.to_string(self.visit_date) if self.visit_date else None,
        }


class VenridesBenrySession(models.Model):
    _name = "venrides.benry.session"
    _description = "Sesión de chat de Benry"
    _order = "last_message_at desc"

    session_id = fields.Char(required=True, index=True)
    company_id = fields.Many2one("venrides.company", string="Empresa", ondelete="set null")
    last_message_at = fields.Datetime(default=fields.Datetime.now)
    summary = fields.Text()
    needs_handoff = fields.Boolean(default=False)
    lead_type = fields.Char()


class VenridesBenryMessage(models.Model):
    _name = "venrides.benry.message"
    _description = "Mensaje de Benry"
    _order = "create_date asc, id asc"

    session_id = fields.Char(required=True, index=True)
    role = fields.Selection([("user", "Usuario"), ("assistant", "Benry")], required=True)
    body = fields.Text(required=True)
