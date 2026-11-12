from odoo import api, fields, models


class VenridesPlanFeature(models.Model):
    _name = "venrides.plan.feature"
    _description = "Característica de plan VenridesScreenS"
    _order = "sequence, id"

    name = fields.Char(string="Característica", required=True, translate=True)
    sequence = fields.Integer(default=10)
    plan_id = fields.Many2one("venrides.plan", string="Plan", required=True, ondelete="cascade")


class VenridesPlan(models.Model):
    _name = "venrides.plan"
    _description = "Plan de VenridesScreenS"
    _order = "sequence, id"
    _rec_name = "name"

    name = fields.Char(string="Nombre", required=True, translate=True)
    code = fields.Char(string="Código", required=True, index=True)
    subtitle = fields.Char(string="Subtítulo", translate=True)
    sequence = fields.Integer(default=10)
    active = fields.Boolean(default=True)
    is_public = fields.Boolean(string="Visible en la web", default=True)
    popular = fields.Boolean(string="Destacado", default=False)
    color = fields.Char(default="#c8ff00")
    monthly_price = fields.Float(string="Precio mensual (USD)", default=0.0)
    annual_price = fields.Float(string="Precio anual (USD)", default=0.0)
    is_custom = fields.Boolean(string="Precio personalizado", default=False)
    max_screens = fields.Integer(string="Máximo de pantallas", default=2, help="0 = ilimitadas")
    max_users = fields.Integer(string="Máximo de usuarios", default=1, help="0 = ilimitados")
    trial_days = fields.Integer(string="Días de prueba", default=7)
    description = fields.Text(string="Descripción", translate=True)

    feature_ids = fields.One2many("venrides.plan.feature", "plan_id", string="Características")

    allow_third_party_ads = fields.Boolean(string="Permite publicidad de terceros", default=True)
    allow_custom_branding = fields.Boolean(string="Permite branding personalizado", default=True)
    allow_sidebar = fields.Boolean(string="Permite barra lateral", default=True)
    allow_bottom_bar = fields.Boolean(string="Permite barra inferior", default=True)
    allow_video_playlist = fields.Boolean(string="Permite playlist de videos", default=True)
    allow_priority_content = fields.Boolean(string="Permite contenido prioritario", default=True)
    allow_bcv = fields.Boolean(string="Permite tasa BCV", default=True)
    allow_multi_user = fields.Boolean(string="Permite múltiples usuarios", default=False)
    allow_helpdesk = fields.Boolean(string="Incluye helpdesk", default=True)
    allow_mobile = fields.Boolean(string="Incluye app móvil", default=False)
    allow_api = fields.Boolean(string="Incluye API", default=False)

    _code_uniq = models.Constraint("UNIQUE(code)", "El código del plan debe ser único.")

    @api.model
    def api_list(self):
        """Planes públicos para la landing."""
        plans = self.search([("active", "=", True), ("is_public", "=", True)], order="sequence, id")
        return [plan.api_dict() for plan in plans]

    def api_dict(self):
        self.ensure_one()
        screens = "Ilimitadas" if self.max_screens == 0 else f"{self.max_screens} pantallas"
        return {
            "id": self.code,
            "code": self.code,
            "name": self.name,
            "subtitle": self.subtitle or "",
            "monthlyPrice": None if self.is_custom else self.monthly_price,
            "annualPrice": None if self.is_custom else self.annual_price,
            "screens": screens,
            "features": [f.name for f in self.feature_ids.sorted("sequence")],
            "popular": self.popular,
            "isCustom": self.is_custom,
            "description": self.description or "",
        }
