from odoo import fields, models


class VenridesPayment(models.Model):
    _name = "venrides.payment"
    _description = "Pago de suscripción VenridesScreenS"
    _order = "payment_date desc, id desc"

    company_id = fields.Many2one("venrides.company", string="Empresa", required=True, ondelete="cascade", index=True)
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
