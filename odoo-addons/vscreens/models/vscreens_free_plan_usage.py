# -*- coding: utf-8 -*-
from odoo import api, fields, models


class VscreensFreePlanUsage(models.Model):
    _name = "vscreens.free.plan.usage"
    _description = "Uso de prueba gratuita por dispositivo VScreenS"
    _order = "used_at desc"
    _rec_name = "uuid"

    uuid = fields.Char(string="UUID del dispositivo", required=True, index=True)
    company_id = fields.Many2one("vscreens.company", string="Empresa", ondelete="cascade")
    used_at = fields.Datetime(string="Usado el", default=fields.Datetime.now)
    expires_at = fields.Datetime(string="Expira el")

    _uuid_uniq = models.Constraint("UNIQUE(uuid)", "Este dispositivo ya utilizó la prueba gratuita.")
