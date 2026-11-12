from odoo import fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    vscreens_api_public_url = fields.Char(
        string="URL pública de la API",
        config_parameter="vscreens.api_public_url",
        default="https://vscreens-api.inverpave.com",
    )
    vscreens_landing_url = fields.Char(
        string="URL de la landing",
        config_parameter="vscreens.landing_url",
        default="https://vscreens.inverpave.com",
    )
    vscreens_admin_url = fields.Char(
        string="URL del panel cliente",
        config_parameter="vscreens.admin_url",
        default="https://vscreens-app.inverpave.com",
    )
    vscreens_tv_url = fields.Char(
        string="URL de la TV",
        config_parameter="vscreens.tv_url",
        default="https://vscreens-tv.inverpave.com",
    )
    vscreens_odoo_url = fields.Char(
        string="URL de Odoo maestro",
        config_parameter="vscreens.odoo_url",
        default="https://vscreens-erp.inverpave.com",
    )
    vscreens_notification_email = fields.Char(
        string="Email de notificaciones",
        config_parameter="vscreens.notification_email",
        default="info.vscreens@inverpave.com",
    )
    vscreens_support_email = fields.Char(
        string="Email de soporte",
        config_parameter="vscreens.support_email",
        default="info.vscreens@inverpave.com",
    )
    vscreens_billing_email = fields.Char(
        string="Email de facturación",
        config_parameter="vscreens.billing_email",
        default="pagos.vscreens@inverpave.com",
    )
