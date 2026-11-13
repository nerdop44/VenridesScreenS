# -*- coding: utf-8 -*-
from odoo import api, fields, models


class VscreensAffiliate(models.Model):
    _name = "vscreens.affiliate"
    _description = "Afiliado VScreenS"
    _order = "created_at desc, id desc"
    _rec_name = "name"

    name = fields.Char(string="Nombre", required=True)
    email = fields.Char(string="Email", required=True, index=True)
    code = fields.Char(string="Código de afiliado", required=True, index=True)
    commission_pct = fields.Float(string="Comisión %", default=10.0)
    total_referred = fields.Integer(string="Total referidos", default=0)
    total_earned = fields.Float(string="Total ganado", default=0.0)
    is_active = fields.Boolean(string="Activo", default=True)
    created_at = fields.Datetime(string="Creado el", default=fields.Datetime.now, readonly=True)

    _code_uniq = models.Constraint("UNIQUE(code)", "El código de afiliado debe ser único.")
    _email_uniq = models.Constraint("UNIQUE(email)", "El email del afiliado debe ser único.")

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email or "",
            "code": self.code or "",
            "commission_pct": self.commission_pct,
            "total_referred": self.total_referred,
            "total_earned": self.total_earned,
            "is_active": self.is_active,
        }
