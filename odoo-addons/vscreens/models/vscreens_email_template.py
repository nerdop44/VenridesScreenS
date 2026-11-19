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
         ("cumpleanos", "Cumpleaños"),
         ("general", "General")],
        string="Categoría", default="general")
    active = fields.Boolean(string="Activa", default=True)
    created_at = fields.Datetime(string="Creado el", default=fields.Datetime.now, readonly=True)

    _name_uniq = models.Constraint("UNIQUE(name)", "La clave de la plantilla debe ser única.")

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
