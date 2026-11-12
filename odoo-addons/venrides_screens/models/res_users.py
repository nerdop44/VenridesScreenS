from odoo import api, fields, models

ROLE_GROUPS = {
    "admin_master": [
        "base.group_user",
        "base.group_system",
        "venrides_screens.group_venrides_master",
    ],
    "admin_empresa": [
        "base.group_portal",
        "venrides_screens.group_venrides_company_admin",
    ],
    "operador_empresa": [
        "base.group_portal",
        "venrides_screens.group_venrides_operator",
    ],
    "user_basic": [
        "base.group_portal",
        "venrides_screens.group_venrides_basic",
    ],
}


class ResUsers(models.Model):
    _inherit = "res.users"

    venrides_company_id = fields.Many2one("venrides.company", string="Empresa VenridesScreenS", ondelete="set null", index=True)
    venrides_role = fields.Selection(
        [
            ("admin_master", "Administrador maestro"),
            ("admin_empresa", "Administrador de empresa"),
            ("operador_empresa", "Operador de empresa"),
            ("user_basic", "Usuario básico"),
        ],
        string="Rol VenridesScreenS",
        default="operador_empresa",
        required=True,
    )
    venrides_permissions = fields.Json(string="Permisos granulares", default=dict)
    venrides_must_change_password = fields.Boolean(string="Debe cambiar contraseña", default=False)
    venrides_legacy_hash = fields.Char(string="Hash legado (argon2)", copy=False)
    venrides_is_master = fields.Boolean(string="¿Es maestro?", compute="_compute_venrides_is_master")
    venrides_company_name = fields.Char(related="venrides_company_id.name", string="Empresa", store=True)

    @api.depends("group_ids")
    def _compute_venrides_is_master(self):
        for user in self:
            user.venrides_is_master = user.has_group("venrides_screens.group_venrides_master")

    def _apply_venrides_role(self):
        for user in self:
            xmlids = ROLE_GROUPS.get(user.venrides_role) or ROLE_GROUPS["operador_empresa"]
            groups = self.env["res.groups"]
            for xmlid in xmlids:
                group = self.env.ref(xmlid, raise_if_not_found=False)
                if group:
                    groups |= group
            if groups:
                user.group_ids = [(6, 0, groups.ids)]

    @api.model_create_multi
    def create(self, vals_list):
        users = super().create(vals_list)
        users._apply_venrides_role()
        return users

    def write(self, vals):
        res = super().write(vals)
        if "venrides_role" in vals:
            self._apply_venrides_role()
        return res

    def set_venrides_role(self, role):
        self.write({"venrides_role": role})

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "username": self.login,
            "is_admin": self.venrides_is_master,
            "role": self.venrides_role,
            "permissions": self.venrides_permissions or {},
            "company_id": self.venrides_company_id.id if self.venrides_company_id else None,
            "must_change_password": self.venrides_must_change_password,
            "is_active": self.active,
            "name": self.name,
        }
