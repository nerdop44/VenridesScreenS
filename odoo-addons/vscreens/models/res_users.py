from odoo import api, fields, models

ROLE_GROUPS = {
    "admin_master": [
        "base.group_user",
        "base.group_system",
        "vscreens.group_vscreens_master",
    ],
    "admin_empresa": [
        "base.group_portal",
        "vscreens.group_vscreens_company_admin",
    ],
    "operador_empresa": [
        "base.group_portal",
        "vscreens.group_vscreens_operator",
    ],
    "user_basic": [
        "base.group_portal",
        "vscreens.group_vscreens_basic",
    ],
}


class ResUsers(models.Model):
    _inherit = "res.users"

    vscreens_company_id = fields.Many2one("vscreens.company", string="Empresa VScreenS", ondelete="set null", index=True)
    vscreens_role = fields.Selection(
        [
            ("admin_master", "Administrador maestro"),
            ("admin_empresa", "Administrador de empresa"),
            ("operador_empresa", "Operador de empresa"),
            ("user_basic", "Usuario básico"),
        ],
        string="Rol VScreenS",
        default="operador_empresa",
        required=True,
    )
    vscreens_permissions = fields.Json(string="Permisos granulares", default=dict)
    vscreens_must_change_password = fields.Boolean(string="Debe cambiar contraseña", default=False)
    vscreens_legacy_hash = fields.Char(string="Hash legado (argon2)", copy=False)
    vscreens_is_master = fields.Boolean(string="¿Es maestro?", compute="_compute_vscreens_is_master")
    vscreens_company_name = fields.Char(related="vscreens_company_id.name", string="Empresa", store=True)

    @api.depends("group_ids")
    def _compute_vscreens_is_master(self):
        for user in self:
            user.vscreens_is_master = user.has_group("vscreens.group_vscreens_master")

    def _apply_vscreens_role(self):
        for user in self:
            xmlids = ROLE_GROUPS.get(user.vscreens_role) or ROLE_GROUPS["operador_empresa"]
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
        users._apply_vscreens_role()
        return users

    def write(self, vals):
        res = super().write(vals)
        if "vscreens_role" in vals:
            self._apply_vscreens_role()
        return res

    def set_vscreens_role(self, role):
        self.write({"vscreens_role": role})

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "username": self.login,
            "is_admin": self.vscreens_is_master,
            "role": self.vscreens_role,
            "permissions": self.vscreens_permissions or {},
            "company_id": self.vscreens_company_id.id if self.vscreens_company_id else None,
            "must_change_password": self.vscreens_must_change_password,
            "is_active": self.active,
            "name": self.name,
        }
