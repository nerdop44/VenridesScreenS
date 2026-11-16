# -*- coding: utf-8 -*-
# Licensed under the LGPLv3 - VScreenS - Localización Venezuela (LocVe)
"""Entregas de productos digitales y aplicación del plan contratado.

Flujo:
1. El cliente compra un producto digital (APK) o un plan en la tienda Odoo.
2. Al confirmarse el pedido se crea una entrega con token único y se envía un
   correo con el enlace de descarga y las instrucciones de activación.
3. El enlace tokenizado permite descargar el archivo, registra la estadística y
   respeta el límite de descargas configurado.
4. Si el pedido incluye un plan, se aplica a la empresa del cliente y se extiende
   su vigencia según los días configurados en el producto.
"""

from datetime import timedelta
import logging
import secrets

from odoo import api, fields, models

_logger = logging.getLogger(__name__)


class VscreensDigitalEntitlement(models.Model):
    _name = "vscreens.digital.entitlement"
    _description = "Entrega de producto digital VScreenS"
    _order = "create_date desc, id desc"
    _rec_name = "product_name"
    _inherit = ["mail.thread"]

    token = fields.Char(
        string="Token de descarga",
        required=True,
        index=True,
        copy=False,
        default=lambda self: secrets.token_urlsafe(32),
    )
    partner_id = fields.Many2one("res.partner", string="Cliente", required=True, ondelete="cascade")
    email = fields.Char(string="Correo de entrega", related="partner_id.email", store=True)
    product_tmpl_id = fields.Many2one(
        "product.template",
        string="Producto",
        required=True,
        ondelete="cascade",
    )
    product_name = fields.Char(string="Producto (nombre)", related="product_tmpl_id.name", store=True)
    order_id = fields.Many2one("sale.order", string="Pedido", ondelete="set null", index=True)
    company_id = fields.Many2one("vscreens.company", string="Empresa VScreenS", ondelete="set null")
    quantity = fields.Float(string="Cantidad", default=1.0)
    download_count = fields.Integer(string="Descargas realizadas", default=0, readonly=True)
    max_downloads = fields.Integer(
        string="Máximo de descargas",
        default=0,
        help="0 = descargas ilimitadas.",
    )
    last_download_at = fields.Datetime(string="Última descarga", readonly=True)
    expires_at = fields.Datetime(string="Válida hasta", readonly=True)
    is_active = fields.Boolean(string="Activa", default=True)
    is_valid = fields.Boolean(string="Descarga disponible", compute="_compute_is_valid")
    notes = fields.Text(string="Notas")

    def _compute_is_valid(self):
        now = fields.Datetime.now()
        for entitlement in self:
            limit_ok = (
                not entitlement.max_downloads
                or entitlement.download_count < entitlement.max_downloads
            )
            entitlement.is_valid = bool(
                entitlement.is_active
                and limit_ok
                and (not entitlement.expires_at or entitlement.expires_at > now)
            )

    def download_url(self):
        self.ensure_one()
        base = self.env["ir.config_parameter"].sudo().get_param("web.base.url", "").rstrip("/")
        return f"{base}/shop/download/{self.token}"

    def register_download(self):
        """Marca una descarga y devuelve el archivo en base64."""
        self.ensure_one()
        if not self.is_valid:
            return False
        self.sudo().write({
            "download_count": self.download_count + 1,
            "last_download_at": fields.Datetime.now(),
        })
        product = self.product_tmpl_id.sudo()
        product.write({"download_count": product.download_count + 1})
        return product.digital_file

    def action_resend_email(self):
        """Reenvía el correo de entrega del pedido asociado."""
        self.ensure_one()
        template = self.env.ref("vscreens.email_template_digital_delivery", raise_if_not_found=False)
        if not self.order_id or not template:
            return {
                "type": "ir.actions.client",
                "tag": "display_notification",
                "params": {
                    "title": "Sin pedido asociado",
                    "message": "Esta entrega no tiene un pedido del cual reenviar el correo.",
                    "type": "warning",
                },
            }
        template.sudo().send_mail(self.order_id.id, force_send=True)
        return {
            "type": "ir.actions.client",
            "tag": "display_notification",
            "params": {
                "title": "Correo reenviado",
                "message": f"Se reenvió la entrega a {self.email or self.partner_id.email or 'sin correo'}.",
                "type": "success",
            },
        }


class SaleOrder(models.Model):
    _inherit = "sale.order"

    vscreens_fulfilled = fields.Boolean(string="Entrega VScreenS realizada", copy=False, readonly=True)
    vscreens_company_id = fields.Many2one("vscreens.company", string="Empresa VScreenS", readonly=True, copy=False)
    vscreens_entitlement_ids = fields.One2many(
        "vscreens.digital.entitlement",
        "order_id",
        string="Entregas digitales",
    )
    vscreens_plan_id = fields.Many2one("vscreens.plan", string="Plan aplicado", readonly=True, copy=False)
    vscreens_valid_until = fields.Datetime(string="Vigencia aplicada", readonly=True, copy=False)

    def action_confirm(self):
        res = super().action_confirm()
        for order in self:
            if not order.vscreens_fulfilled:
                order._vscreens_fulfill()
        return res

    # ------------------------------------------------------------------
    # Entrega
    # ------------------------------------------------------------------
    def _vscreens_resolve_company(self, plan=None):
        """Devuelve (o crea) la empresa VScreenS asociada al cliente del pedido."""
        self.ensure_one()
        Company = self.env["vscreens.company"].sudo()
        company = Company.search([("partner_id", "=", self.partner_id.id)], limit=1)
        if company:
            return company
        free_plan = self.env["vscreens.plan"].sudo().search([("code", "=", "free")], limit=1)
        fallback_plan = plan or free_plan or self.env["vscreens.plan"].sudo().search([], limit=1)
        if not fallback_plan:
            return Company
        partner = self.partner_id.commercial_partner_id
        return Company.create({
            "name": partner.name or partner.display_name or self.partner_id.name,
            "partner_id": self.partner_id.id,
            "plan_id": fallback_plan.id,
            "email": self.partner_id.email or False,
            "phone": self.partner_id.phone or False,
            "whatsapp": self.partner_id.mobile or False,
            "rif": self.partner_id.vat or False,
            "address": self.partner_id.contact_address or False,
            "is_active": True,
        })

    def _vscreens_fulfill(self):
        self.ensure_one()
        Entitlement = self.env["vscreens.digital.entitlement"].sudo()
        digital_lines = self.order_line.filtered(
            lambda line: line.product_id.is_digital and line.product_id.digital_file
        )
        plan_lines = self.order_line.filtered(lambda line: line.product_id.plan_id)
        if not digital_lines and not plan_lines:
            self.sudo().write({"vscreens_fulfilled": True})
            return

        plan = plan_lines[:1].product_id.plan_id
        company = self._vscreens_resolve_company(plan=plan)

        # --- Productos digitales: una entrega por línea ---
        for line in digital_lines:
            product = line.product_id.product_tmpl_id
            Entitlement.create({
                "partner_id": self.partner_id.id,
                "product_tmpl_id": product.id,
                "order_id": self.id,
                "company_id": company.id if company else False,
                "quantity": line.product_uom_qty,
                "max_downloads": 0,
                "expires_at": fields.Datetime.now() + timedelta(days=365),
                "notes": f"Pedido {self.name}",
            })

        # --- Plan contratado: aplicarlo a la empresa ---
        valid_until = False
        if company and plan_lines:
            now = fields.Datetime.now()
            base = company.valid_until if company.valid_until and company.valid_until > now else now
            days = sum(
                (line.product_id.plan_days or 30) * int(max(line.product_uom_qty, 1))
                for line in plan_lines
            )
            valid_until = base + timedelta(days=days)
            company.sudo().write({
                "plan_id": plan.id,
                "valid_until": valid_until,
                "is_active": True,
                "plan_activated_at": company.plan_activated_at or now,
            })
            self.sudo().write({
                "vscreens_plan_id": plan.id,
                "vscreens_valid_until": valid_until,
            })
            self.env["vscreens.payment"].sudo().create({
                "company_id": company.id,
                "amount": self.amount_total,
                "payment_method": "Ecommerce",
                "description": f"Pedido {self.name} — {plan.name}",
                "reference": self.name,
                "state": "confirmed",
                "notes": "Generado automáticamente desde la tienda en línea.",
            })

        self.sudo().write({
            "vscreens_fulfilled": True,
            "vscreens_company_id": company.id if company else False,
        })

        # --- Correo de entrega ---
        template = self.env.ref("vscreens.email_template_digital_delivery", raise_if_not_found=False)
        try:
            if template:
                template.sudo().send_mail(self.id, force_send=True)
            else:
                self._vscreens_send_fallback_mail()
        except Exception as error:  # noqa: BLE001 - la venta no debe romperse por el correo
            _logger.warning("VScreenS: no se pudo enviar el correo de entrega del pedido %s: %s", self.name, error)

    def _vscreens_send_fallback_mail(self):
        self.ensure_one()
        lines = "<br/>".join(
            f"- {ent.product_name}: <a href='{ent.download_url()}'>{ent.download_url()}</a>"
            for ent in self.vscreens_entitlement_ids
        )
        body = (
            f"<p>Hola {self.partner_id.name or ''},</p>"
            f"<p>Gracias por tu compra <strong>{self.name}</strong>.</p>"
            f"<p>{lines}</p>"
            "<p>Instala el APK y activa tu dispositivo desde el panel de clientes.</p>"
        )
        self.env["mail.mail"].sudo().create({
            "subject": f"Tu compra en VScreenS — {self.name}",
            "email_to": self.partner_id.email,
            "body_html": body,
            "model": "sale.order",
            "res_id": self.id,
        }).send()
