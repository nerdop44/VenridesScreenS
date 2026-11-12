from datetime import timedelta

from odoo import api, fields, models


class VScreenSDevice(models.Model):
    _name = "vscreens.device"
    _description = "Pantalla / dispositivo VScreenS"
    _order = "name, id"
    _rec_name = "name"

    uuid = fields.Char(string="UUID", required=True, index=True, copy=False)
    name = fields.Char(string="Nombre", required=True)
    company_id = fields.Many2one("vscreens.company", string="Empresa", required=True, ondelete="cascade", index=True)
    last_ping = fields.Datetime(string="Última conexión", default=fields.Datetime.now, index=True)
    is_active = fields.Boolean(string="Activa", default=True)
    last_ip = fields.Char(string="Última IP")
    ping_requested_at = fields.Datetime(string="Ping solicitado")

    is_online = fields.Boolean(string="En línea", compute="_compute_is_online")

    _uuid_uniq = models.Constraint("UNIQUE(uuid)", "El UUID de la pantalla debe ser único.")

    @api.depends("last_ping")
    def _compute_is_online(self):
        now = fields.Datetime.now()
        for device in self:
            device.is_online = bool(device.last_ping and (now - device.last_ping) < timedelta(minutes=5))

    def register_ping(self, ip=None):
        self.ensure_one()
        vals = {"last_ping": fields.Datetime.now()}
        if ip:
            vals["last_ip"] = ip
        self.sudo().write(vals)

    def action_ping(self):
        self.ensure_one()
        self.write({"ping_requested_at": fields.Datetime.now()})
        return True

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "uuid": self.uuid,
            "name": self.name,
            "company_id": self.company_id.id,
            "company_name": self.company_id.name,
            "last_ping": fields.Datetime.to_string(self.last_ping) if self.last_ping else None,
            "is_online": self.is_online,
            "is_active": self.is_active,
        }
