# -*- coding: utf-8 -*-
from datetime import datetime

from odoo import api, fields, models


class VscreensCalendarActivity(models.Model):
    _name = "vscreens.calendar.activity"
    _description = "Actividad / Feriado del calendario VScreenS"
    _order = "activity_date"
    _rec_name = "title"

    title = fields.Char(string="Título", required=True)
    description = fields.Text(string="Descripción")
    activity_date = fields.Date(string="Fecha", required=True, index=True)
    is_holiday = fields.Boolean(string="¿Es feriado?", default=False)
    send_auto_greeting = fields.Boolean(string="Enviar saludo automático", default=False,
                                        help="Si está activo, se envía un saludo automático por email en esta fecha")
    greeting_template_id = fields.Many2one("vscreens.email.template", string="Plantilla de saludo")
    created_at = fields.Datetime(string="Creado el", default=fields.Datetime.now, readonly=True)

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "title": self.title or "",
            "description": self.description or "",
            "activity_date": fields.Date.to_string(self.activity_date) if self.activity_date else None,
            "is_holiday": self.is_holiday,
            "send_auto_greeting": self.send_auto_greeting,
        }

    @api.model
    def seed_venezuelan_holidays(self, year=None):
        """Siembra los feriados nacionales de Venezuela para el año dado."""
        if not year:
            year = datetime.now().year
        holidays = [
            ("Año Nuevo", 1, 1),
            ("Carnaval (Lunes)", 2, 16),
            ("Carnaval (Martes)", 2, 17),
            ("Jueves Santo", 4, 2),
            ("Viernes Santo", 4, 3),
            ("Declaración de Independencia", 4, 19),
            ("Día del Trabajador", 5, 1),
            ("Batalla de Carabobo", 6, 24),
            ("Día de la Independencia", 7, 5),
            ("Natalicio del Libertador", 7, 24),
            ("Día de la Resistencia Indígena", 10, 12),
            ("Navidad", 12, 25),
            ("Fin de Año", 12, 31),
        ]
        created = 0
        updated = 0
        for title, month, day in holidays:
            date = datetime(year, month, day).date()
            existing = self.sudo().search([
                ("title", "=", title),
                ("is_holiday", "=", True),
                ("activity_date", "=", date),
            ], limit=1)
            if not existing:
                self.sudo().create({
                    "title": title,
                    "description": f"Feriado Nacional: {title}",
                    "activity_date": date,
                    "is_holiday": True,
                    "send_auto_greeting": True,
                })
                created += 1
            else:
                if existing.activity_date != date:
                    existing.sudo().write({"activity_date": date})
                    updated += 1
        return {"status": "success", "created": created, "updated": updated}
