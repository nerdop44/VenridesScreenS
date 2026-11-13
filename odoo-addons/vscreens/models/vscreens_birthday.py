# -*- coding: utf-8 -*-
import logging

from odoo import api, fields, models

_logger = logging.getLogger(__name__)


class ResPartner(models.Model):
    _inherit = "res.partner"

    @api.model
    def _cron_send_birthday_greetings(self):
        """Cron diario: envía saludos de cumpleaños a contactos cuyo cumpleaños es hoy."""
        today = fields.Date.today()
        partners = self.sudo().search([
            ("birthday", "!=", False),
            ("email", "!=", False),
        ])
        sent = 0
        template = self.env["vscreens.email.template"].sudo().search(
            [("category", "=", "bienvenida"), ("active", "=", True)], limit=1
        )
        for partner in partners:
            if partner.birthday.month == today.month and partner.birthday.day == today.day:
                try:
                    self.env["mail.mail"].sudo().create({
                        "subject": template.subject or "¡Feliz cumpleaños!",
                        "body_html": template.body or f"<p>¡Feliz cumpleaños, {partner.name}!</p>",
                        "email_to": partner.email,
                        "email_from": self.env["ir.config_parameter"].sudo().get_str(
                            "vscreens.notification_email", "info.vscreens@inverpave.com"),
                    }).send()
                    sent += 1
                except Exception as exc:
                    _logger.warning("No se pudo enviar cumpleaños a %s: %s", partner.email, exc)
        _logger.info("Cron cumpleaños: %d saludos enviados", sent)
        return sent
