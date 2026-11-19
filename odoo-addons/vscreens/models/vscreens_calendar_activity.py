# -*- coding: utf-8 -*-
from datetime import date, datetime, timedelta

from odoo import api, fields, models


def _easter_sunday(year):
    """Algoritmo gregoriano (Meeus/Jones/Butcher) para calcular Domingo de Pascua."""
    a = year % 19
    b = year // 100
    c = year % 100
    d = b // 4
    e = b % 4
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i = c // 4
    k = c % 4
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    month = (h + l - 7 * m + 114) // 31
    day = ((h + l - 7 * m + 114) % 31) + 1
    return date(year, month, day)


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
        """Siembra los feriados nacionales de Venezuela para el año dado (incluyendo móviles)."""
        if not year:
            year = datetime.now().year
        easter = _easter_sunday(year)
        carnaval_lun = easter - timedelta(days=48)
        carnaval_mar = easter - timedelta(days=47)
        jueves_santo = easter - timedelta(days=3)
        viernes_santo = easter - timedelta(days=2)
        holidays = [
            ("Año Nuevo", date(year, 1, 1)),
            ("Carnaval (Lunes)", carnaval_lun),
            ("Carnaval (Martes)", carnaval_mar),
            ("Jueves Santo", jueves_santo),
            ("Viernes Santo", viernes_santo),
            ("Declaración de Independencia", date(year, 4, 19)),
            ("Día del Trabajador", date(year, 5, 1)),
            ("Batalla de Carabobo", date(year, 6, 24)),
            ("Día de la Independencia", date(year, 7, 5)),
            ("Natalicio del Libertador", date(year, 7, 24)),
            ("Día de la Resistencia Indígena", date(year, 10, 12)),
            ("Navidad", date(year, 12, 25)),
            ("Fin de Año", date(year, 12, 31)),
        ]
        created = 0
        updated = 0
        for title, hdate in holidays:
            existing = self.sudo().search([
                ("title", "=", title),
                ("is_holiday", "=", True),
                ("activity_date", ">=", date(year, 1, 1)),
                ("activity_date", "<=", date(year, 12, 31)),
            ], limit=1)
            if not existing:
                self.sudo().create({
                    "title": title,
                    "description": f"Feriado Nacional: {title}",
                    "activity_date": hdate,
                    "is_holiday": True,
                    "send_auto_greeting": True,
                })
                created += 1
            elif existing.activity_date != hdate:
                existing.sudo().write({"activity_date": hdate})
                updated += 1
        return {"status": "success", "created": created, "updated": updated}
