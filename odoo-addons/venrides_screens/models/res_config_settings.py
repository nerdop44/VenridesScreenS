from odoo import fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    venrides_api_public_url = fields.Char(
        string="URL pública de la API",
        config_parameter="venrides.api_public_url",
        default="https://venrides-api.inverpave.com",
    )
    venrides_landing_url = fields.Char(
        string="URL de la landing",
        config_parameter="venrides.landing_url",
        default="https://venrides.inverpave.com",
    )
    venrides_admin_url = fields.Char(
        string="URL del panel cliente",
        config_parameter="venrides.admin_url",
        default="https://venrides-app.inverpave.com",
    )
    venrides_tv_url = fields.Char(
        string="URL de la TV",
        config_parameter="venrides.tv_url",
        default="https://venrides-tv.inverpave.com",
    )
    venrides_odoo_url = fields.Char(
        string="URL de Odoo maestro",
        config_parameter="venrides.odoo_url",
        default="https://venrides-erp.inverpave.com",
    )
    venrides_notification_email = fields.Char(
        string="Email de notificaciones",
        config_parameter="venrides.notification_email",
        default="soporte@inverpave.com",
    )
    venrides_support_email = fields.Char(
        string="Email de soporte",
        config_parameter="venrides.support_email",
        default="soporte@inverpave.com",
    )
    venrides_billing_email = fields.Char(
        string="Email de facturación",
        config_parameter="venrides.billing_email",
        default="pagos@inverpave.com",
    )
