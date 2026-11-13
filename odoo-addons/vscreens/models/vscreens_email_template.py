# -*- coding: utf-8 -*-
from odoo import api, fields, models


class VscreensEmailTemplate(models.Model):
    _name = "vscreens.email.template"
    _description = "Plantilla de email VScreenS"
    _order = "category, name"
    _rec_name = "name"

    name = fields.Char(string="Nombre", required=True, index=True)
    subject = fields.Char(string="Asunto", required=True)
    body = fields.Html(string="Cuerpo HTML", required=True)
    default_subject = fields.Char(string="Asunto original")
    default_body = fields.Html(string="Cuerpo original")
    is_system = fields.Boolean(string="Plantilla del sistema", default=False,
                               help="Las plantillas del sistema no se pueden eliminar, solo revertir")
    category = fields.Selection(
        [("bienvenida", "Bienvenida"),
         ("cobranza", "Cobranza"),
         ("marketing", "Marketing"),
         ("soporte", "Soporte"),
         ("general", "General")],
        string="Categoría", default="general")
    active = fields.Boolean(string="Activa", default=True)
    created_at = fields.Datetime(string="Creado el", default=fields.Datetime.now, readonly=True)

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "name": self.name,
            "subject": self.subject or "",
            "body": self.body or "",
            "default_subject": self.default_subject or "",
            "default_body": self.default_body or "",
            "is_system": self.is_system,
            "category": self.category or "general",
            "is_active": self.active,
        }
