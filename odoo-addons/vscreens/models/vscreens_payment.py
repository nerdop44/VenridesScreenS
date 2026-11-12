from odoo import fields, models
from odoo.exceptions import UserError


class VScreenSPayment(models.Model):
    _name = "vscreens.payment"
    _description = "Pago de suscripción VScreenS"
    _order = "payment_date desc, id desc"

    company_id = fields.Many2one("vscreens.company", string="Empresa", required=True, ondelete="cascade", index=True)
    amount = fields.Monetary(string="Monto", required=True, currency_field="currency_id")
    currency_id = fields.Many2one("res.currency", string="Moneda", required=True, default=lambda self: self.env.company.currency_id)
    payment_method = fields.Char(string="Método de pago")
    description = fields.Char(string="Descripción")
    payment_date = fields.Datetime(string="Fecha de pago", default=fields.Datetime.now, required=True)
    state = fields.Selection(
        [("draft", "Borrador"), ("confirmed", "Confirmado"), ("cancelled", "Cancelado")],
        default="confirmed",
        string="Estado",
    )
    reference = fields.Char(string="Referencia")
    notes = fields.Text(string="Notas")
    account_move_id = fields.Many2one("account.move", string="Factura", readonly=True, copy=False)

    def _ensure_partner(self):
        self.ensure_one()
        company = self.company_id
        if company.partner_id:
            return company.partner_id
        partner = self.env["res.partner"].sudo().create({
            "name": company.name,
            "email": company.email or False,
            "phone": company.phone or False,
            "is_company": True,
            "customer_rank": 1,
            "street": company.address or False,
            "vat": company.rif or False,
        })
        company.sudo().write({"partner_id": partner.id})
        return partner

    def action_create_invoice(self):
        self.ensure_one()
        if self.account_move_id:
            return self.action_view_invoice()
        partner = self._ensure_partner()
        journal = self.env["account.journal"].sudo().search(
            [("type", "=", "sale"), ("company_id", "=", self.env.company.id)], limit=1
        )
        if not journal:
            raise UserError("No hay diario de ventas configurado. Configure la contabilidad de la empresa.")
        move = self.env["account.move"].sudo().create({
            "move_type": "out_invoice",
            "partner_id": partner.id,
            "invoice_date": self.payment_date.date() if self.payment_date else fields.Date.today(),
            "currency_id": self.currency_id.id,
            "journal_id": journal.id,
            "invoice_origin": self.description or "VScreenS",
            "invoice_line_ids": [(0, 0, {
                "name": self.description or "Suscripción VScreenS",
                "quantity": 1.0,
                "price_unit": self.amount,
                "tax_ids": [(6, 0, [])],
            })],
        })
        self.sudo().write({"account_move_id": move.id})
        return self.action_view_invoice()

    def action_view_invoice(self):
        self.ensure_one()
        return {
            "type": "ir.actions.act_window",
            "name": "Factura",
            "res_model": "account.move",
            "res_id": self.account_move_id.id,
            "view_mode": "form",
            "target": "current",
        }

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "company_id": self.company_id.id,
            "amount": self.amount,
            "currency": self.currency_id.name,
            "payment_method": self.payment_method or "",
            "description": self.description or "",
            "payment_date": fields.Datetime.to_string(self.payment_date) if self.payment_date else None,
            "state": self.state,
            "reference": self.reference or "",
        }
