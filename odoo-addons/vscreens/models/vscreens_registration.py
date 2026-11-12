import secrets
from datetime import timedelta

from odoo import api, fields, models
from odoo.exceptions import UserError


class VScreenSRegistrationCode(models.Model):
    _name = "vscreens.registration.code"
    _description = "Código de vinculación de pantalla"
    _order = "create_date desc"

    code = fields.Char(string="Código", required=True, index=True)
    company_id = fields.Many2one("vscreens.company", string="Empresa", required=True, ondelete="cascade")
    expires_at = fields.Datetime(string="Expira el", required=True)
    used = fields.Boolean(default=False)

    _code_uniq = models.Constraint("UNIQUE(code)", "El código debe ser único.")

    @api.model
    def _cleanup_expired(self):
        self.sudo().search([("expires_at", "<", fields.Datetime.now())]).unlink()

    @api.model
    def generate_for_company(self, company):
        self._cleanup_expired()
        for _ in range(100):
            code = "".join(str(secrets.randbelow(10)) for _ in range(6))
            if not self.sudo().search_count([("code", "=", code)]):
                rec = self.sudo().create({
                    "code": code,
                    "company_id": company.id,
                    "expires_at": fields.Datetime.now() + timedelta(minutes=10),
                })
                return {"code": rec.code, "expires_in_minutes": 10}
        raise UserError("No se pudo generar un código único.")

    @api.model
    def validate_for_device(self, code, device_uuid, ip=None):
        self._cleanup_expired()
        reg = self.sudo().search([("code", "=", code), ("used", "=", False)], limit=1)
        if not reg:
            return False, {"status": 404, "detail": "Código inválido"}

        if reg.expires_at < fields.Datetime.now():
            reg.unlink()
            return False, {"status": 400, "detail": "Código expirado"}

        company = reg.company_id
        if not company._can_add_device():
            return False, {"status": 400, "detail": "Límite de pantallas alcanzado"}

        device = self.env["vscreens.device"].sudo().search([("uuid", "=", device_uuid)], limit=1)

        if (company.plan_code or "").lower() == "free":
            usage = self.env["vscreens.free.plan.usage"].sudo().search([("uuid", "=", device_uuid)], limit=1)
            if usage and usage.company_id.id != company.id:
                return False, {"status": 403, "detail": "DEVICE_BLOCKED_FREE_TRIAL_USED"}
            if not usage:
                self.env["vscreens.free.plan.usage"].sudo().create({
                    "uuid": device_uuid,
                    "company_id": company.id,
                })
            if not company.plan_activated_at:
                trial_days = company.plan_id.trial_days or 7
                company.sudo().write({
                    "plan_activated_at": fields.Datetime.now(),
                    "valid_until": fields.Datetime.now() + timedelta(days=trial_days),
                })
            if not company.first_screen_connected_at:
                company.sudo().write({"first_screen_connected_at": fields.Datetime.now()})

        if device:
            device.sudo().write({"company_id": company.id, "last_ip": ip or device.last_ip})
        else:
            device = self.env["vscreens.device"].sudo().create({
                "uuid": device_uuid,
                "company_id": company.id,
                "name": f"TV-{device_uuid[:8]}",
                "last_ip": ip,
            })

        reg.unlink()
        return True, company.device_config(device)


class VScreenSFreePlanUsage(models.Model):
    _name = "vscreens.free.plan.usage"
    _description = "Uso de prueba gratuita por dispositivo"
    _order = "used_at desc"

    uuid = fields.Char(string="UUID", required=True, index=True)
    company_id = fields.Many2one("vscreens.company", string="Empresa", ondelete="cascade")
    used_at = fields.Datetime(default=fields.Datetime.now)
    expires_at = fields.Datetime()

    _uuid_uniq = models.Constraint("UNIQUE(uuid)", "Este dispositivo ya utilizó la prueba gratuita.")
