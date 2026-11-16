# -*- coding: utf-8 -*-
# Licensed under the LGPLv3 - VScreenS - Localización Venezuela (LocVe)

from odoo import api, fields, models
from odoo.exceptions import UserError, ValidationError
import logging

_logger = logging.getLogger(__name__)


class ProductTemplate(models.Model):
    _inherit = "product.template"

    is_digital = fields.Boolean(
        string="Producto Digital",
        default=False,
        help="Si está marcado, el producto es un archivo descargable (APK, etc.) y no un producto físico.",
    )
    digital_file = fields.Binary(
        string="Archivo Digital",
        attachment=True,
        help="Archivo para descarga (ej. APK de la app TV o móvil).",
    )
    digital_filename = fields.Char(string="Nombre del Archivo")
    download_count = fields.Integer(
        string="Descargas",
        default=0,
        readonly=True,
        help="Número de veces que se ha descargado este archivo.",
    )
    is_operational_only_when_activated = fields.Boolean(
        string="Solo operativo si está activado",
        default=True,
        help="Si está marcado, el archivo se puede descargar libremente pero solo funciona si el dispositivo está activado en el panel de clientes.",
    )
    plan_id = fields.Many2one(
        "vscreens.plan",
        string="Plan VScreenS",
        help="Si el producto representa un plan, al confirmarse la compra se aplica este plan a la empresa del cliente.",
    )
    plan_days = fields.Integer(
        string="Días de vigencia por unidad",
        default=30,
        help="Días que se suman a la vigencia de la empresa por cada unidad comprada.",
    )


class ProductProduct(models.Model):
    _inherit = "product.product"

    is_digital = fields.Boolean(related="product_tmpl_id.is_digital", store=True, readonly=False)
    digital_file = fields.Binary(related="product_tmpl_id.digital_file", readonly=False)
    digital_filename = fields.Char(related="product_tmpl_id.digital_filename", readonly=False)
    download_count = fields.Integer(related="product_tmpl_id.download_count", readonly=True)
    is_operational_only_when_activated = fields.Boolean(
        related="product_tmpl_id.is_operational_only_when_activated",
        readonly=False,
    )
    plan_id = fields.Many2one(related="product_tmpl_id.plan_id", readonly=False)
    plan_days = fields.Integer(related="product_tmpl_id.plan_days", readonly=False)


class VscreensDeviceActivation(models.Model):
    _name = "vscreens.device.activation"
    _description = "Activación de Dispositivo VScreenS"
    _order = "activated_at desc, id desc"
    _rec_name = "device_uuid"

    device_uuid = fields.Char(string="UUID del Dispositivo", required=True, index=True)
    device_name = fields.Char(string="Nombre del Dispositivo")
    device_type = fields.Selection(
        [("tv", "TV"), ("mobile", "Móvil"), ("tablet", "Tablet")],
        string="Tipo de Dispositivo",
        required=True,
    )
    company_id = fields.Many2one(
        "vscreens.company",
        string="Empresa / Cliente",
        required=True,
        ondelete="cascade",
    )
    partner_id = fields.Many2one(
        "res.partner",
        string="Contacto",
        related="company_id.partner_id",
        store=True,
    )
    is_active = fields.Boolean(string="Activo", default=True, tracking=True)
    activated_at = fields.Datetime(string="Activado el", default=fields.Datetime.now, readonly=True)
    deactivated_at = fields.Datetime(string="Desactivado el")
    last_ping_at = fields.Datetime(string="Último ping")
    download_product_id = fields.Many2one(
        "product.template",
        string="Producto Descargado",
        help="Producto digital (APK) asociado a esta activación.",
    )
    notes = fields.Text(string="Notas")

    _uuid_uniq = models.Constraint(
        "UNIQUE(device_uuid)", "Este dispositivo ya está activado."
    )

    def action_deactivate(self):
        self.ensure_one()
        self.write({"is_active": False, "deactivated_at": fields.Datetime.now()})
        return True

    def action_activate(self):
        self.ensure_one()
        self.write({"is_active": True, "activated_at": fields.Datetime.now(), "deactivated_at": False})
        return True


class VscreensDownloadStat(models.Model):
    _name = "vscreens.download.stat"
    _description = "Estadísticas de Descarga VScreenS"
    _order = "downloaded_at desc, id desc"
    _rec_name = "product_name"

    product_id = fields.Many2one(
        "product.template",
        string="Producto",
        required=True,
        ondelete="cascade",
    )
    product_name = fields.Char(
        string="Nombre del Producto",
        related="product_id.name",
        store=True,
    )
    downloaded_at = fields.Datetime(string="Descargado el", default=fields.Datetime.now, readonly=True)
    ip_address = fields.Char(string="Dirección IP")
    user_agent = fields.Char(string="User Agent")
    company_id = fields.Many2one(
        "vscreens.company",
        string="Empresa",
        help="Empresa que realizó la descarga (si se identificó).",
    )
    device_uuid = fields.Char(string="UUID del Dispositivo")
    is_authorized = fields.Boolean(
        string="Autorizado",
        default=False,
        help="Si el dispositivo estaba autorizado para usar el producto.",
    )


class VscreensCompany(models.Model):
    _inherit = "vscreens.company"

    device_activation_ids = fields.One2many(
        "vscreens.device.activation",
        "company_id",
        string="Dispositivos Activados",
    )
    device_activation_count = fields.Integer(
        string="Número de Dispositivos",
        compute="_compute_device_activation_count",
    )

    @api.depends("device_activation_ids")
    def _compute_device_activation_count(self):
        for rec in self:
            rec.device_activation_count = len(rec.device_activation_ids)
