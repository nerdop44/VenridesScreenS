from odoo import fields, models


class VenridesApiToken(models.Model):
    _name = "venrides.api.token"
    _description = "Token de API VenridesScreenS"
    _order = "create_date desc"

    token = fields.Char(required=True, index=True)
    user_id = fields.Many2one("res.users", string="Usuario", required=True, ondelete="cascade", index=True)
    expires_at = fields.Datetime(required=True)
    active = fields.Boolean(default=True)
    last_used_at = fields.Datetime()

    _sql_constraints = [
        ("token_uniq", "unique(token)", "El token debe ser único."),
    ]
