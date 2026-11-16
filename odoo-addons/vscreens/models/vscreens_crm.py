# -*- coding: utf-8 -*-
# Licensed under the LGPLv3 - VScreenS - Localización Venezuela (LocVe)

from datetime import timedelta
import logging

from odoo import api, fields, models

FOLLOWUP_DAYS = 3
FOLLOWUP_LIMIT = 3


class CrmLead(models.Model):
    _inherit = "crm.lead"

    vscreens_plan_interest = fields.Char(string="Plan de interés")
    vscreens_source_detail = fields.Char(string="Origen VScreenS")
    vscreens_contact_name = fields.Char(string="Nombre de contacto VScreenS")

    # Seguimiento automático
    vscreens_followup_active = fields.Boolean(
        string="Seguimiento automático",
        default=True,
        copy=False,
        help="Si está activo, el lead recibe correos de seguimiento automáticos.",
    )
    vscreens_followup_count = fields.Integer(
        string="Seguimientos enviados",
        default=0,
        copy=False,
        readonly=True,
    )
    vscreens_last_followup = fields.Datetime(
        string="Último seguimiento",
        copy=False,
        readonly=True,
    )
    vscreens_next_followup = fields.Datetime(
        string="Próximo seguimiento",
        copy=False,
        default=lambda self: fields.Datetime.now() + timedelta(days=FOLLOWUP_DAYS),
    )

    # ------------------------------------------------------------------
    # Envío de correos
    # ------------------------------------------------------------------
    def _vscreens_followup_template(self):
        return self.env.ref("vscreens.email_template_crm_followup", raise_if_not_found=False)

    def _vscreens_send_followup_mail(self, email=None, force_subject=False):
        """Envía el correo de seguimiento y actualiza el estado del lead."""
        self.ensure_one()
        template = self._vscreens_followup_template()
        if not template:
            return False
        target = (email or self.email_from or "").strip()
        if not target:
            return False
        template.sudo().send_mail(
            self.id,
            email_values={"email_to": target},
            force_send=True,
        )
        if not email:
            count = self.vscreens_followup_count + 1
            next_date = (
                fields.Datetime.now() + timedelta(days=FOLLOWUP_DAYS)
                if count < FOLLOWUP_LIMIT
                else False
            )
            self.sudo().write({
                "vscreens_followup_count": count,
                "vscreens_last_followup": fields.Datetime.now(),
                "vscreens_next_followup": next_date,
                "vscreens_followup_active": bool(next_date),
            })
        self.message_post(
            body=f"Correo de seguimiento enviado a {target}."
        )
        return True

    def action_send_followup(self):
        """Botón: envía el seguimiento ahora y reprograma el siguiente."""
        sent = 0
        for lead in self:
            if lead.email_from and lead._vscreens_send_followup_mail():
                sent += 1
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": "Seguimiento enviado",
                "message": f"Se envió el correo a {sent} lead(s).",
                "type": "success" if sent else "warning",
            },
        }

    def action_send_test_email(self):
        """Botón: verifica el envío real de correo sin afectar el seguimiento."""
        self.ensure_one()
        target = (
            self.email_from
            or self.env.company.email
            or self.env.user.email
            or self.env["ir.config_parameter"].sudo().get_str("vscreens.test_email", "")
        )
        if not target:
            return {
                "type": "ir.actions.client",
                "tag": "display_notification",
                "params": {
                    "title": "Sin correo de destino",
                    "message": "Agrega un correo al lead o configura un correo de prueba.",
                    "type": "warning",
                },
            }
        self._vscreens_send_followup_mail(email=target)
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": "Correo de prueba enviado",
                "message": f"Se envió una prueba a {target}.",
                "type": "success",
            },
        }

    def action_send_mass_followup(self):
        """Acción masiva: envía el seguimiento a los leads seleccionados."""
        sent = 0
        skipped = 0
        for lead in self:
            if lead.email_from:
                if lead._vscreens_send_followup_mail():
                    sent += 1
            else:
                skipped += 1
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": "Correo masivo",
                "message": f"Enviados: {sent}. Sin correo: {skipped}.",
                "type": "success" if sent else "warning",
            },
        }

    # ------------------------------------------------------------------
    # Cron de seguimiento
    # ------------------------------------------------------------------
    @api.model
    def _cron_crm_followup(self):
        now = fields.Datetime.now()
        leads = self.sudo().search([
            ("vscreens_followup_active", "=", True),
            ("vscreens_next_followup", "!=", False),
            ("vscreens_next_followup", "<=", now),
            ("vscreens_followup_count", "<", FOLLOWUP_LIMIT),
            ("email_from", "!=", False),
            ("active", "=", True),
            ("stage_id.is_won", "=", False),
        ])
        sent = 0
        for lead in leads:
            try:
                with self.env.cr.savepoint():
                    if lead._vscreens_send_followup_mail():
                        sent += 1
            except Exception as error:  # noqa: BLE001 - un lead no debe detener el cron
                logging.getLogger(__name__).warning(
                    "VScreenS CRM: no se pudo enviar seguimiento al lead %s: %s",
                    lead.id,
                    error,
                )
        return sent
