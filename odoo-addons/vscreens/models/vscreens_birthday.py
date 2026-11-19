# -*- coding: utf-8 -*-
import logging

from odoo import api, fields, models

_logger = logging.getLogger(__name__)


class ResPartner(models.Model):
    _inherit = "res.partner"

    @api.model
    def _cron_send_birthday_greetings(self):
        """Cron diario: envía saludos de cumpleaños a empresas VScreenS cuya fecha coincide con hoy."""
        today = fields.Date.today()
        companies = self.env["vscreens.company"].sudo().search([
            ("birthday", "!=", False),
            ("email", "!=", False),
            ("is_active", "=", True),
        ])
        sent = 0
        template = self.env["vscreens.email.template"].sudo().search(
            [("category", "in", ("cumpleanos", "birthday", "saludo")), ("active", "=", True)], limit=1
        )
        email_from = self.env["ir.config_parameter"].sudo().get_str(
            "vscreens.notification_email", "info.vscreens@inverpave.com"
        )
        for company in companies:
            if company.birthday.month == today.month and company.birthday.day == today.day:
                contact = company.contact_person or company.name
                subject = (template.subject if template and template.subject else "¡Feliz cumpleaños de parte de VScreenS!")
                body_html = (template.body if template and template.body else f"<p>¡Feliz cumpleaños, {contact}! Te desea el equipo de VScreenS.</p>")
                subject = subject.replace("{{contacto}}", contact).replace("{{empresa}}", company.name)
                body_html = body_html.replace("{{contacto}}", contact).replace("{{empresa}}", company.name)
                try:
                    self.env["mail.mail"].sudo().create({
                        "subject": subject,
                        "body_html": body_html,
                        "email_to": company.email,
                        "email_from": email_from,
                    }).send()
                    sent += 1
                except Exception as exc:
                    _logger.warning("No se pudo enviar cumpleaños a %s: %s", company.email, exc)
        _logger.info("Cron cumpleaños: %d saludos enviados", sent)
        return sent
