# -*- coding: utf-8 -*-
from odoo import api, fields, models


class VscreensPromotion(models.Model):
    _name = "vscreens.promotion"
    _description = "Promoción VScreenS"
    _order = "created_at desc, id desc"
    _rec_name = "name"

    name = fields.Char(string="Nombre", required=True)
    description = fields.Text(string="Descripción")
    code = fields.Char(string="Código de promoción", required=True, index=True)
    discount_pct = fields.Float(string="Descuento %", default=0.0)
    valid_from = fields.Datetime(string="Válido desde")
    valid_to = fields.Datetime(string="Válido hasta")
    is_active = fields.Boolean(string="Activa", default=True)
    created_at = fields.Datetime(string="Creado el", default=fields.Datetime.now, readonly=True)

    _code_uniq = models.Constraint("UNIQUE(code)", "El código de promoción debe ser único.")

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description or "",
            "code": self.code or "",
            "discount_pct": self.discount_pct,
            "valid_from": fields.Datetime.to_string(self.valid_from) if self.valid_from else None,
            "valid_to": fields.Datetime.to_string(self.valid_to) if self.valid_to else None,
            "is_active": self.is_active,
        }
