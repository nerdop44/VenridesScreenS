# -*- coding: utf-8 -*-
from odoo import api, fields, models, _
from odoo.exceptions import UserError
from odoo.tools import float_is_zero, float_repr

class ProductProduct(models.Model):
    _inherit = 'product.product'

    # 'currency_id_dif' y 'cost_currency_id' NO se redefinen aqui como compute:
    # product_template.py ya los declara en la variante como
    # related='product_tmpl_id.*'. Mantener ambas definiciones en el mismo
    # modelo hacia que gane la ultima y Odoo 20 avisaba
    # "Field product.product.X is both compute and related".

    # ------------------------------------------------------------------
    # Anclaje del costo (port a Odoo 20)
    #
    # En Odoo 20 el costo maestro vive en la VARIANTE: 'standard_price' es un
    # campo almacenado y company_dependent, mientras que en la plantilla es un
    # proxy que delega en sus variantes. El campo maestro de la doble moneda es
    # 'standard_price_usd' (definido en product.template y delegado aqui).
    #
    # Se redefine 'standard_price' como almacenado y calculado a partir del
    # maestro en divisa, de modo que:
    #   - escribir standard_price_usd actualiza el costo en moneda local
    #     (necesario porque el core valoriza desde la variante), y
    #   - escribir standard_price (por ejemplo el AVCO automatico del core)
    #     recalcula el maestro en divisa, manteniendo ambas monedas cuadradas.
    # ------------------------------------------------------------------

    standard_price = fields.Float(
        'Cost',
        company_dependent=True,
        compute='_compute_standard_price_dual_currency',
        inverse='_inverse_standard_price_dual_currency',
        store=True,
        readonly=False,
        min_display_digits='Product Price',
        groups="base.group_user",
    )

    def _dual_currency_tasa(self):
        """Tasa de la divisa de referencia usada para convertir el costo."""
        company = self.company_id or self.env.company
        if company.currency_id.name == 'USD':
            return 1.0
        return company.currency_id_dif.get_trm_systray() if company.currency_id_dif else 0.0

    @api.depends('standard_price_usd', 'company_id.currency_id')
    def _compute_standard_price_dual_currency(self):
        for rec in self:
            tasa = rec._dual_currency_tasa()
            rec.standard_price = rec.standard_price_usd * tasa if tasa > 0 else rec.standard_price_usd

    def _inverse_standard_price_dual_currency(self):
        for rec in self:
            tasa = rec._dual_currency_tasa()
            val = rec.standard_price / tasa if tasa > 0 else rec.standard_price
            template = rec.product_tmpl_id
            if abs(template.standard_price_usd - val) > 1e-5:
                template.standard_price_usd = val

    @api.onchange('standard_price')
    def _onchange_standard_price(self):
        for rec in self:
            rec._inverse_standard_price_dual_currency()

    @api.depends('standard_price', 'currency_id_dif')
    def _compute_standard_price_bs(self):
        for rec in self:
            company = rec.env.company
            tasa = company.currency_id_dif.get_trm_systray() if company.currency_id_dif else 0.0
            rec.standard_price_bs = rec.standard_price * tasa if tasa > 0 else 0.0

    # ------------------------------------------------------------------
    # Valorizacion de inventario en divisa de referencia.
    #
    # Odoo 20 elimino el modelo 'stock.valuation.layer': las capas de
    # valoracion son ahora los propios 'stock.move' valorizados, que
    # acumalan 'value' / 'remaining_qty' / 'remaining_value', y el
    # historial de ajustes vive en 'product.value'.
    #
    # El equivalente de los campos USD que se extendian sobre SVL
    # (value_usd, remaining_value_usd, unit_cost_usd, tasa) se defining
    # en models/stock_move.py; aqui solo se agregan los agregados a nivel
    # de producto.
    # ------------------------------------------------------------------

    value_usd_svl = fields.Float(
        string='Valor total ($)', compute='_compute_value_usd_svl', compute_sudo=True)

    @api.depends_context('to_date', 'company')
    def _compute_value_usd_svl(self):
        """Valor del inventario en divisa de referencia.

        Suma el valor remanente en USD de los movimientos de entrada de cada
        producto. El remanente lo calcula 'stock.move._compute_remaining_value'
        a partir de 'remaining_qty', por lo que se recorre en Python en vez de
        usar '_read_group': no es un campo almacenado y el nucleo solo admite
        agregarlo mediante '_read_group_select' con 'id:recordset'.
        """
        if not self:
            return
        company = self.env.company
        currency = company.currency_id_dif
        if not currency:
            self.value_usd_svl = 0.0
            return
        domain = [
            ('product_id', 'in', self.ids),
            ('company_id', '=', company.id),
            ('is_in', '=', True),
        ]
        if self.env.context.get('to_date'):
            domain.append(('date', '<=', self.env.context['to_date']))
        moves = self.env['stock.move'].with_company(company).sudo().search(domain)
        total_by_product = {}
        for move in moves:
            total_by_product[move.product_id] = (
                total_by_product.get(move.product_id, 0.0) + move.remaining_value_usd)
        for product in self:
            product.value_usd_svl = currency.round(total_by_product.get(product, 0.0))

    @api.onchange('standard_price_usd')
    def _onchange_standard_price_usd(self):
        # Inhabilitado: el costo maestro ahora es standard_price (USD)
        pass

    # ------------------------------------------------------------------
    # _prepare_in_svl_vals / _prepare_out_svl_vals y el _run_fifo propio de
    # LocVe se retiraron: Odoo 20 ya no invoca esos metodos y la valorizacion
    # se resuelve en stock.move._get_value() / _set_value(). Ademas la
    # firma de _run_fifo cambio por completo en el core
    # (_run_fifo(at_date, lot, correction) -> (std_prices, total_values)),
    # por lo que sobrescribirla habria roto el FIFO nativo.
    #
    # La equivalencia en divisa de referencia se calcula ahora en
    # models/stock_move.py, que extiende 'stock.move'.
    # ------------------------------------------------------------------

    def price_compute(self, price_type, uom=False, currency=False, company=None, date=False):
        company = company or self.env.company
        date = date or fields.Date.context_today(self)

        self = self.with_company(company)
        if price_type == 'standard_price':
            # standard_price field can only be seen by users in base.group_user
            # Thus, in order to compute the sale price from the cost for users not in this group
            # We fetch the standard price as the superuser
            self = self.sudo()

        prices = dict.fromkeys(self.ids, 0.0)
        for product in self:
            prices[product.id] = product[price_type if not price_type == 'standard_price' else 'standard_price_usd'] or 0.0
            if price_type == 'standard_price':
                prices[product.id] = prices[product.id] * self.env.company.currency_id_dif.inverse_rate
            if price_type == 'list_price':
                prices[product.id] += product.price_extra
                # we need to add the price from the attributes that do not generate variants
                # (see field product.attribute create_variant)
                if self._context.get('no_variant_attributes_price_extra'):
                    # we have a list of price_extra that do not generate variants
                    prices[product.id] += sum(self._context.get('no_variant_attributes_price_extra'))

            if uom:
                prices[product.id] = product.uom_id._compute_price(prices[product.id], uom)

            # Convert from current user company currency to asked one
            # This is right cause a field cannot be in more than one currency
            #if currency:
            #    price = price_currency._convert(price, currency, company, date)

        return prices
