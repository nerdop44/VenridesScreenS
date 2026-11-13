from odoo import api, fields, models, _
from lxml import etree
###
from odoo.sql_db import SQL
###

class AccountInvoiceReport(models.Model):
    _inherit = "account.invoice.report"
    _auto = False

    def default_alternate_currency(self):
        """
        This method is used to get the foreign currency of the company and set it as the default value of the foreign currency field

        Returns
        -------
        type = int
            The id of the foreign currency of the company

        """
        alternate_currency = self.env.company.currency_foreign_id.id
        if alternate_currency:
            return alternate_currency
        return False

    foreign_currency_id = fields.Many2one(
        "res.currency",
        default=default_alternate_currency,
    )

    foreign_rate = fields.Float(
        help="Foreign Rate of the invoice",
        readonly=True,
        digits="Tasa",
    )
    foreign_subtotal = fields.Monetary(
        help="Foreign Total of the invoice",
        readonly=True,
        currency_field="foreign_currency_id",
    )
    foreign_price_total = fields.Monetary(
        help="Foreign Total of the invoice",
        readonly=True,
        currency_field="foreign_currency_id",
    )

    _depends = {
        "account.move.line": ["foreign_rate", "foreign_subtotal", "foreign_price_total"],
    }

    def _select_list(self, table):
        """
        Agrega al SELECT de account.invoice.report las columnas de la
        moneda extranjera (rate / subtotales / total) definidas en
        account.move.line por l10n_ve_accountant.

        Odoo 20 sustituyo el antiguo ``_select()`` (que devolvia una cadena
        SQL concatenada con la tabla ``line``) por ``_select_list(table)``,
        que devuelve una lista de expresiones ``SQL``/``TableSQL`` sobre la
        tabla real de account.move.line.
        """
        return [
            *super()._select_list(table),
            SQL("%s AS foreign_currency_id", table.foreign_currency_id),
            SQL("%s AS foreign_rate", table.foreign_rate),
            SQL("%s AS foreign_subtotal", table.foreign_subtotal),
            SQL("%s AS foreign_price_total", table.foreign_price_total),
        ]
        

    @api.model
    def get_view(self, view_id=None, view_type=None, **options):
        """
        This method is used to add the symbol of the foreign currency to the foreign_rate and foreign_total_billed fields in the view

        Returns
        -------
        type = dict
            The view with the symbol of the foreign currency

        """
        res = super().get_view(view_id=view_id, view_type=view_type, **options)
        foreign_currency_id = self.env.company.currency_foreign_id.id
        if foreign_currency_id:
            foreign_currency_record = self.env["res.currency"].search(
                [("id", "=", int(foreign_currency_id))]
            )
            foreign_currency_symbol = foreign_currency_record.symbol
            doc = etree.XML(res["arch"])
            foreign_total_billed = doc.xpath("//field[@name='foreign_subtotal']")
            foreign_rate = doc.xpath("//field[@name='foreign_rate']")
            foreign_price_total = doc.xpath("//field[@name='foreign_price_total']")
            if foreign_total_billed:
                foreign_total_billed[0].set(
                    "string", "Total Billed (" + foreign_currency_symbol + ")"
                )
                res["arch"] = etree.tostring(doc, encoding="unicode")
            if foreign_rate:
                foreign_rate[0].set("string", "Foreign Rate (" + foreign_currency_symbol + ")")
                res["arch"] = etree.tostring(doc, encoding="unicode")

            if foreign_price_total:
                foreign_price_total[0].set(
                    "string", "Foreign Total (" + foreign_currency_symbol + ")"
                )
                res["arch"] = etree.tostring(doc, encoding="unicode")

        return res
