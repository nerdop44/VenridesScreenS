from odoo import fields, models


class VenridesGenerateCodeWizard(models.TransientModel):
    _name = "venrides.generate.code.wizard"
    _description = "Generar código de vinculación"

    company_id = fields.Many2one("venrides.company", string="Empresa", required=True)
    code = fields.Char(string="Código", readonly=True)
    expires_in_minutes = fields.Integer(string="Vigencia (min)", default=10, readonly=True)

    def action_generate(self):
        self.ensure_one()
        result = self.env["venrides.registration.code"].generate_for_company(self.company_id)
        self.write({
            "code": result.get("code"),
            "expires_in_minutes": result.get("expires_in_minutes", 10),
        })
        return {
            "type": "ir.actions.act_window",
            "res_model": self._name,
            "res_id": self.id,
            "view_mode": "form",
            "target": "new",
        }


class VenridesSendAlertWizard(models.TransientModel):
    _name = "venrides.send.alert.wizard"
    _description = "Enviar alerta en vivo"

    company_id = fields.Many2one("venrides.company", string="Empresa", required=True)
    text = fields.Text(string="Mensaje", required=True)
    duration = fields.Integer(string="Duración (s)", default=15)

    def action_send(self):
        self.ensure_one()
        self.env["venrides.message"].create({
            "company_id": self.company_id.id,
            "subject": "¡AVISO IMPORTANTE!",
            "body": self.text,
            "is_alert": True,
            "alert_duration": self.duration,
            "is_read": False,
        })
        return {"type": "ir.actions.act_window_close"}
