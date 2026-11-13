import datetime

from odoo import api, fields, models


class StockMove(models.Model):
    """Valorizacion de inventario en divisa de referencia sobre stock.move.

    En Odoo <= 18 las capas de valoracion eran registros independientes del
    modelo 'stock.valuation.layer'. En Odoo 20 ese modelo se elimino: cada
    'stock.move' valorizado es ahora su propia capa y acumula 'value' y
    'remaining_value'. Este archivo traslada la doble moneda que se
    extendia sobre SVL a los movimientos de almacen.

    Equivalencia de campos:
        SVL.value_usd           -> move.value_usd
        SVL.remaining_value_usd -> move.remaining_value_usd
        SVL.unit_cost_usd       -> move.unit_cost_usd
        SVL.tasa                -> move.tasa
        SVL.stock_move_id       -> el propio move

    Nota sobre FIFO: en Odoo 20 la valoracion de las salidas ya no se
    descuenta capa por capa, sino que se recalcula desde cero con
    '_get_fifo_stack()'. Por eso el enganche correcto es '_set_value()',
    que es el unico punto donde el core asigna 'move.value' para entradas
    y salidas, en lugar de replicar el recorrido de capas que ya no existe.
    """

    _inherit = 'stock.move'

    currency_id_dif = fields.Many2one(
        "res.currency",
        string="Divisa de Referencia",
        default=lambda self: self.env.company.currency_id_dif,
    )
    unit_cost_usd = fields.Monetary(
        'Valor unitario $', readonly=True, default=0, currency_field='currency_id_dif')
    value_usd = fields.Monetary(
        'Valor Total $', readonly=True, default=0, currency_field='currency_id_dif')
    remaining_value_usd = fields.Monetary(
        'Valor Restante $', compute='_compute_remaining_value_usd',
        currency_field='currency_id_dif')
    # Este campo almacena la tasa INVERSA (divisa alterna por unidad de
    # moneda base), no la tasa BCV. Una tasa BCFHi se expresa como
    # "bolivares por dolar" (~36.5), donde 4 decimales bastan, pero su
    # inversa (~0.02739726) necesita manyos mas: redondearla a 4 decimales
    # la convierte en 0.0274 y exagera en 36.5x todo importe en divisa
    # (4500 / 0.0274 = 164233.58 en vez de 164250.00). Por eso se almacena
    # con 10 decimales. La tasa BCV que se muestra al usuario se mantiene
    # aparte con 4 decimales, que es la convencion de la regla del proyecto.
    tasa = fields.Float('Tasa de Referencia', readonly=True, digits=(16, 10))

    @api.depends('remaining_value', 'tasa', 'currency_id_dif')
    def _compute_remaining_value_usd(self):
        """Valor remanente del movimiento en divisa de referencia.

        Se calcula en vez de almacenarse porque 'remaining_value' del core ya
        es un campo no almacenado que depende de 'remaining_qty': guardarlo
        en '_set_value' dejaba un valor obsoleto en cuanto otra salida
        consumia parte de la capa, que es justamente el caso que debe
        reflejarse.
        """
        for move in self:
            currency = move.currency_id_dif
            if not currency or not move.tasa:
                move.remaining_value_usd = 0.0
                continue
            move.remaining_value_usd = currency.round(move.remaining_value / move.tasa)

    def _get_dif_rate(self, company=None):
        """Tasa de referencia aplicable al movimiento.

        Prioridad: tasa propia del movimiento, luego tasa de la fecha de
        transferencia del picking, y por ultimo la tasa vigente de la
        empresa.
        """
        self.ensure_one()
        company = company or self.company_id
        currency = company.currency_id_dif
        new_rate = currency.inverse_rate
        if currency:
            date = datetime.date.today()
            if self.picking_id:
                date = self.picking_id.date_of_transfer or self.picking_id.create_date
            # Odoo 20: '_get_rates' devuelve {id: (rate, fecha)}; el helper
            # '_get_rate_value' desempaqueta la tupla.
            rate = currency._get_rate_value(company, date)
            if rate:
                new_rate = 1 / rate
        if self.tasa:
            new_rate = self.tasa
        return new_rate

    def _set_value(self, recompute_date=None, skip_check=False):
        """Punto de enganche de la doble moneda.

        El core asigna aqui 'move.value'. Despues de que el core termine
        su calculo en moneda local, se derivan los importes en divisa de
        referencia usando la misma tasa base, de modo que ambas monedas
        queden siempre cuadradas entre si.
        """
        res = super(StockMove, self)._set_value(
            recompute_date=recompute_date, skip_check=skip_check)
        self._sync_dual_currency_valuation()
        return res

    def _get_landed_cost_local_and_usd(self):
        """Costo adicional de landed cost del movimiento, en ambas monedas.

        El modulo 'stock_landed_costs' inyecta el costo adicional en moneda
        local dentro de '_get_value_from_extra'. Para no convertir ese
        importe a la tasa del picking (que es la del documento original, no la
        del gasto añadido), se separa del valor antes de convertir y se suma
        su equivalente en divisa, que trae el propio ajuste.
        """
        self.ensure_one()
        domain = [('move_id', '=', self.id), ('cost_id.state', '=', 'done')]
        adjustments = self.env['stock.valuation.adjustment.lines'].sudo().search(domain)
        local = sum(adjustments.mapped('additional_landed_cost'))
        usd = sum(adjustments.mapped('additional_landed_cost_usd'))
        return local, usd

    def _sync_dual_currency_valuation(self):
        """Deriva los campos USD a partir del valor ya calculado por el core."""
        for move in self:
            company = move.company_id
            currency = company.currency_id_dif
            if not currency or not move.product_id:
                continue
            if not move.value and not move.remaining_value:
                continue
            tasa = move._get_dif_rate(company)
            if not tasa:
                continue
            qty = move.product_uom_qty
            # El valor local ya trae el landed cost; se separa para convertir
            # solo la parte que corresponde al costo del producto y sumar
            # despues el importe ya valuado en divisa del ajuste.
            extra_local, extra_usd = move._get_landed_cost_local_and_usd()
            base_value = move.value - extra_local
            value_usd = currency.round(base_value / tasa) + extra_usd
            # El costo unitario se mantiene positivo aunque el movimiento sea de
            # salida, igual que en la version anterior sobre SVL: solo el valor
            # total lleva el signo de la direccion del movimiento.
            unit_cost_usd = currency.round(abs(value_usd) / qty) if qty else 0.0
            move.sudo().write({
                'unit_cost_usd': unit_cost_usd,
                'value_usd': value_usd,
                'tasa': round(tasa, 10),
            })
            # En recepciones el costo maestro en divisa se sincroniza con el
            # costo unitario recibido, igual que hacia el core con
            # '_update_standard_price' para la moneda local.
            #
            # OJO: 'value_usd'/'unit_cost_usd' estan expresados en la DIVISA
            # ALTERNA ('currency_id_dif'), mientras que 'standard_price_usd' y
            # el 'standard_price' del core estan en la MONEDA BASE (USD en una
            # empresa con base USD). Tomar 'unit_cost_usd' aqui escribia un
            # importe en VES dentro de un campo en USD, inflando el costo
            # maestro y todo el inventario por el factor de cambio
            # (16.425 Bs en vez de 450 USD). Se usa 'move.value', que el core
            # ya calcula en la moneda base, y se convierte a divisa con la
            # misma tasa para el caso de que la base no sea la divisa.
            if move.location_id.usage == 'supplier' and qty:
                product = move.product_id.with_company(company.id)
                if product.cost_method in ('average', 'fifo'):
                    base_unit = abs(base_value) / qty if base_value else 0.0
                    if company.currency_id.name == 'USD':
                        cost_usd = currency.round(base_unit)
                    else:
                        cost_usd = currency.round(base_unit / tasa)
                    product.sudo().standard_price_usd = cost_usd
        return True

    def create(self, vals_list):
        """Fija la tasa de referencia al crear el movimiento.

        El valor en divisa lo calcula despues el core en '_set_value'; aqui
        solo se persiste la tasa que ese calculo va a necesitar.
        """
        single = isinstance(vals_list, dict)
        vals_list = [vals_list] if single else vals_list
        new_moves = super(StockMove, self).create(vals_list)
        for move, vals in zip(new_moves, vals_list):
            if move.company_id.currency_id_dif and not vals.get('tasa'):
                move.sudo().tasa = round(move._get_dif_rate(), 10)
        return new_moves
