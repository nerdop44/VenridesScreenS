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
import string

from odoo import api, fields, models

_logger = logging.getLogger(__name__)


def _binary_content(value):
    """Devuelve bytes desde un campo binario de Odoo 20 o desde base64."""
    if not value:
        return b""
    content = getattr(value, "content", None)
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    import base64

    return base64.b64decode(value)


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
        base = self.env["ir.config_parameter"].sudo().get_str("web.base.url", "").rstrip("/")
        return f"{base}/shop/download/{self.token}"

    def register_download(self):
        """Marca una descarga y devuelve el contenido binario del archivo."""
        self.ensure_one()
        if not self.is_valid:
            return False
        self.sudo().write({
            "download_count": self.download_count + 1,
            "last_download_at": fields.Datetime.now(),
        })
        product = self.product_tmpl_id.sudo()
        product.write({"download_count": product.download_count + 1})
        return _binary_content(product.digital_file)

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
    vscreens_download_code_ids = fields.One2many(
        "vscreens.download.code",
        "order_id",
        string="Códigos de descarga",
    )
    vscreens_plan_id = fields.Many2one("vscreens.plan", string="Plan aplicado", readonly=True, copy=False)
    vscreens_valid_until = fields.Datetime(string="Vigencia aplicada", readonly=True, copy=False)
    vscreens_panel_login = fields.Char(string="Usuario panel cliente", readonly=True, copy=False)
    vscreens_panel_temp_password = fields.Char(string="Contraseña temporal panel", readonly=True, copy=False)

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
        if not company and self.partner_id.email:
            company = Company.search([("email", "=", self.partner_id.email)], limit=1)
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
            "max_screens": 0,  # Hereda el límite del plan (no 2 fijo)
            "email": self.partner_id.email or False,
            "phone": self.partner_id.phone or False,
            "rif": self.partner_id.vat or False,
            "address": self.partner_id.contact_address or False,
            "is_active": True,
        })

    def _vscreens_ensure_client_user(self, company):
        """Asegura que la empresa tenga un usuario admin_empresa para ingresar al panel web.
        Retorna (login, temp_password_or_empty)."""
        self.ensure_one()
        if not company:
            return "", ""
        existing = company.user_ids.filtered(lambda u: u.active and u.vscreens_role == "admin_empresa")[:1]
        if existing:
            return existing.login, ""
        login = (self.partner_id.email or company.email or "").strip().lower()
        if not login:
            return "", ""
        User = self.env["res.users"].sudo()
        user_by_login = User.with_context(active_test=False).search([("login", "=", login)], limit=1)
        if user_by_login:
            vals = {"vscreens_company_id": company.id, "active": True}
            if not user_by_login.has_group("vscreens.group_vscreens_master"):
                vals["vscreens_role"] = "admin_empresa"
            user_by_login.write(vals)
            return user_by_login.login, ""
        alphabet = string.ascii_letters + string.digits
        temp_password = "".join(secrets.choice(alphabet) for _ in range(10))
        User.create({
            "name": self.partner_id.name or company.name,
            "login": login,
            "email": login,
            "password": temp_password,
            "vscreens_role": "admin_empresa",
            "vscreens_company_id": company.id,
            "vscreens_must_change_password": True,
        })
        return login, temp_password

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
        panel_login, temp_password = self._vscreens_ensure_client_user(company)

        # --- Productos digitales: una entrega por línea ---
        entitled_products = self.env["product.template"].sudo()
        for line in digital_lines:
            product = line.product_id.product_tmpl_id
            entitled_products |= product
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

        # --- Un plan incluye las apps: entregar los APK gratuitos ---
        if plan_lines:
            apps = self.env["product.template"].sudo().search([
                ("is_digital", "=", True),
                ("digital_file", "!=", False),
                ("list_price", "=", 0),
            ]) - entitled_products
            for product in apps:
                entitled_products |= product
                Entitlement.create({
                    "partner_id": self.partner_id.id,
                    "product_tmpl_id": product.id,
                    "order_id": self.id,
                    "company_id": company.id if company else False,
                    "quantity": 1,
                    "max_downloads": 0,
                    "expires_at": fields.Datetime.now() + timedelta(days=365),
                    "notes": f"Incluido en el plan — pedido {self.name}",
                })

        # --- Códigos cortos de descarga (con soporte AFTVnews + /dl/) ---
        if not self.vscreens_download_code_ids:
            Code = self.env["vscreens.download.code"].sudo()
            for product in entitled_products:
                Code.generate(
                    product=product,
                    company=company,
                    partner=self.partner_id,
                    order=self,
                    notes=f"Pedido {self.name}",
                )

        # --- Plan contratado: aplicarlo a la empresa ---
        valid_until = False
        if company and plan_lines:
            now = fields.Datetime.now()
            base = company.valid_until if company.valid_until and company.valid_until > now else now
            days = sum(
                (line.product_id.plan_days or (plan.trial_days if plan.code == "free" else 30))
                * int(max(line.product_uom_qty, 1))
                for line in plan_lines
            )
            valid_until = base + timedelta(days=days)
            company.sudo().write({
                "plan_id": plan.id,
                "max_screens": 0,  # Resetea override para tomar el límite del nuevo plan
                "valid_until": valid_until,
                "is_active": True,
                "plan_activated_at": company.plan_activated_at or now,
            })
            self.sudo().write({
                "vscreens_plan_id": plan.id,
                "vscreens_valid_until": valid_until,
            })
            self.env["vscreens.payment"].sudo().with_context(skip_extend_valid_until=True).create({
                "company_id": company.id,
                "amount": self.amount_total,
                "payment_method": "Ecommerce",
                "description": f"Pedido {self.name} — {plan.name}",
                "reference": self.name,
                "duration_days": days,
                "state": "confirmed",
                "notes": "Generado automáticamente desde la tienda en línea.",
            })

        self.sudo().write({
            "vscreens_fulfilled": True,
            "vscreens_company_id": company.id if company else False,
            "vscreens_panel_login": panel_login or False,
            "vscreens_panel_temp_password": temp_password or False,
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
        finally:
            # No dejamos la contraseña temporal almacenada en texto plano tras enviar el correo
            if temp_password:
                self.sudo().write({"vscreens_panel_temp_password": False})

    def _vscreens_send_fallback_mail(self):
        self.ensure_one()
        lines = "<br/>".join(
            f"- {code.product_name}: <strong style='font-size:20px;letter-spacing:3px;'>{code.code}</strong> "
            f"(<a href='{code.download_url()}'>{code.download_url()}</a>)"
            for code in self.vscreens_download_code_ids
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
