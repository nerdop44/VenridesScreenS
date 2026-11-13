from collections import defaultdict
from contextlib import contextmanager
from datetime import date, timedelta
from functools import lru_cache

from odoo import api, fields, models, Command, _
from odoo.exceptions import ValidationError, UserError
from odoo.tools import frozendict, formatLang, format_date, float_compare
from odoo.tools.float_utils import float_compare, float_is_zero

class AccountMoveLine(models.Model):
    _inherit = 'account.move.line'

    def _valid_field_parameter(self, field_name, parameter):
        return super()._valid_field_parameter(field_name, parameter)


    # -------------------------------------------------------------------------
    # IMPORTES DUALES: Float con 4 decimales, NO Monetary. Son el resultado de
    # una conversion por la TRM; como Monetary heredarian los 2 decimales de
    # VES y perderian el 4to decimal del redondeo. Los importes normales de la
    # linea (debit, credit, price_unit) NO se tocan.
    # -------------------------------------------------------------------------
    debit_usd = fields.Float(
        string='Débito $', store=True, compute="_debit_usd",
        readonly=False, digits=(16, 4))

    credit_usd = fields.Float(
        string='Crédito $', store=True, compute="_credit_usd",
        readonly=False, digits=(16, 4))

    tax_today = fields.Float(related="move_id.tax_today", store=True, string="Tasa del Asiento",
                            digits=(16, 4))
    currency_id_dif = fields.Many2one("res.currency", related="move_id.currency_id_dif", store=True)
    price_unit_usd = fields.Monetary(currency_field='currency_id_dif', string='Precio $', store=True,
                                     compute='_price_unit_usd', readonly=False)

    price_subtotal_usd = fields.Float(
        string='SubTotal $', store=True, compute="_price_subtotal_usd", digits=(16, 4))

    amount_residual_usd = fields.Monetary(string='Residual Amount USD', compute='_compute_amount_residual_usd', store=True,
                                       help="The residual amount on a journal item expressed in the company currency.")

    balance_usd = fields.Float(
        string='Balance Ref.', store=True, readonly=False,
        compute='_compute_balance_usd',
        default=lambda self: self._compute_balance_usd(),
        help="Technical field holding the debit_usd - credit_usd in order to open meaningful graph views from reports",
        digits=(16, 4))


    @api.depends('currency_id', 'company_id', 'move_id.date','move_id.tax_today')
    def _compute_currency_rate(self):

        @lru_cache()
        def get_rate(from_currency, to_currency, company, date):
            rate = self.env['res.currency']._get_conversion_rate(
                from_currency=from_currency,
                to_currency=to_currency,
                company=company,
                date=date,
            )

            return rate

        for line in self:
            if line.currency_id == line.company_currency_id:
                line.currency_rate = 1.0
            else:
                if line.company_currency_id.name == 'USD':
                    raw_rate = line.move_id.tax_today if line.move_id.tax_today > 0 else 1.0
                else:
                    raw_rate = 1.0 / line.move_id.tax_today if line.move_id.tax_today > 0 else 1.0
                from odoo.tools.float_utils import float_round as _fr
                line.currency_rate = _fr(raw_rate, precision_digits=6)

    @api.onchange('amount_currency')
    def _onchange_amount_currency(self):
        self._debit_usd()
        self._credit_usd()

    @api.onchange('price_unit_usd')
    def _onchange_price_unit_usd(self):
        for rec in self:
            rate = rec.move_id.tax_today or rec.move_id.foreign_rate or 1.0
            if rec.move_id.currency_id and rec.move_id.currency_id.name == 'USD':
                rec.price_unit = rec.price_unit_usd
            else:
                rec.price_unit = rec.price_unit_usd * rate

    @api.depends('product_id', 'move_id.currency_id', 'move_id.tax_today')
    def _compute_price_unit(self):
        # v302 - `move_id._context` no existe: el contexto vive en `self.env.context`.
        # Esta linea reventaba con AttributeError en CUALQUIER creacion de un
        # account.move.line (extracto bancario, asientos de sesion POS, facturas),
        # porque el compute se dispara siempre al crear la linea.
        skip_lines = self.filtered(
            lambda l: l.sale_line_ids or l.purchase_line_id
                      or l.move_id.invoice_origin
                      or self.env.context.get('default_invoice_origin')
        )
        remaining = self - skip_lines
        if not remaining:
            return
        saved_prices = {}
        for line in remaining:
            if line.product_id and line.price_unit:
                saved_prices[line.id] = line.price_unit
        super(AccountMoveLine, remaining)._compute_price_unit()
        for line in remaining:
            if line.id in saved_prices and line.product_id:
                saved = saved_prices[line.id]
                list_price = line.product_id.list_price or 0.0
                if abs(saved - list_price) > 0.01:
                    line.price_unit = saved

    def _apply_dual_currency_price(self):
        for line in self:
            if not line.product_id or line.display_type:
                continue
            list_price = line.product_id.list_price or 0.0
            current_price = line.price_unit or 0.0
            if list_price > 0 and current_price > 0 and abs(current_price - list_price) > 0.01:
                continue
            rate = line.move_id.tax_today or 1.0
            master_usd = line.product_id.list_price_usd or 0.0
            company = line.company_id or line.env.company
            if company.currency_id.name == 'USD':
                if line.move_id.currency_id and line.move_id.currency_id.name == 'USD':
                    line.price_unit = master_usd
                else:
                    line.price_unit = master_usd * rate
            else:
                list_price_bs = line.product_id.list_price_bs or 0.0
                if line.move_id.currency_id and line.move_id.currency_id.name == 'USD':
                    line.price_unit = master_usd
                else:
                    line.price_unit = list_price_bs if list_price_bs > 0 else (master_usd * rate)



    @api.onchange('product_id')
    def _onchange_product_id(self):
        self._apply_dual_currency_price()

    @api.onchange('price_unit')
    def _onchange_price_unit_warning(self):
        for line in self:
            if line.move_id.move_type in ('out_invoice', 'out_refund', 'in_invoice', 'in_refund') and not line.display_type:
                if line.price_unit <= 0.0 and line.product_id:
                    return {
                        'warning': {
                            'title': _("Precio Inválido"),
                            'message': _("El precio unitario de la línea '%s' no puede ser 0.0 o negativo.") % (line.product_id.display_name or line.name)
                        }
                    }

    @api.depends('debit_usd', 'credit_usd')
    def _compute_balance_usd(self):
        for line in self:
            line.balance_usd = round(line.debit_usd - line.credit_usd, 4)

    @api.depends('price_unit', 'product_id', 'move_id.currency_id', 'move_id.tax_today', 'company_currency_id')
    def _price_unit_usd(self):
        for rec in self:
            rate = rec.move_id.tax_today or rec.move_id.foreign_rate or 1.0
            if rec.price_unit > 0:
                is_doc_usd = rec.move_id.currency_id and rec.move_id.currency_id.name == 'USD'
                if is_doc_usd:
                    rec.price_unit_usd = rec.price_unit
                else:
                    # Redondeo DESPUES del 4to decimal: la tasa del dia ya
                    # tiene 4 decimales, y el resultado se fija tambien a 4
                    # para que el valor dual sea reproducible y auditable.
                    rec.price_unit_usd = round(rec.price_unit / rate, 4) if rate > 0 else 0
            else:
                rec.price_unit_usd = 0

    @api.depends('price_subtotal', 'tax_today', 'move_id.currency_id', 'company_currency_id')
    def _price_subtotal_usd(self):
        for rec in self:
            if rec.price_subtotal > 0:
                is_doc_usd = rec.move_id.currency_id and rec.move_id.currency_id.name == 'USD'
                if is_doc_usd:
                    rec.price_subtotal_usd = rec.price_subtotal
                else:
                    rec.price_subtotal_usd = round(rec.price_subtotal / rec.tax_today, 4) if rec.tax_today > 0 else 0
            else:
                rec.price_subtotal_usd = 0

            # if rec.price_subtotal_usd > 0:
            #     if rec.move_id.currency_id == self.env.company.currency_id:
            #         rec.price_subtotal = rec.price_subtotal_usd * rec.tax_today
            #     else:
            #         rec.price_subtotal = rec.price_subtotal_usd
            # else:
            #     rec.price_subtotal = 0

    # Odoo 20: read_group() cambio de firma y ahora es keyword-only
    # (domain, groupby=, aggregates=, having=, offset=, limit=, order=).
    # El override anterior solo pretendia exponer 'tax_today' en los grupos,
    # pero tax_today ya no es un campo almacenado, por lo que no puede
    # agruparse. Se delega en la implementacion nativa del ORM.
    read_group = models.Model.read_group

    @api.depends('debit', 'tax_today')
    def _debit_usd(self):
        for rec in self:
            if rec.company_id.currency_id.name == 'USD':
                rec.debit_usd = rec.debit
            else:
                rec.debit_usd = round(rec.debit / rec.tax_today, 4) if rec.tax_today > 0 else 0

    @api.depends('credit', 'tax_today')
    def _credit_usd(self):
        for rec in self:
            if rec.company_id.currency_id.name == 'USD':
                rec.credit_usd = rec.credit
            else:
                rec.credit_usd = round(rec.credit / rec.tax_today, 4) if rec.tax_today > 0 else 0

    @api.depends('debit','credit','debit_usd', 'credit_usd', 'amount_currency', 'account_id', 'currency_id', 'move_id.state',
                 'company_id',
                 'matched_debit_ids', 'matched_credit_ids')
    def _compute_amount_residual_usd(self):
        """ Computes the residual amount of a move line from a reconcilable account in the company currency and the line's currency.
            This amount will be 0 for fully reconciled lines or lines from a non-reconcilable account, the original line amount
            for unreconciled lines, and something in-between for partially reconciled lines.
        """
        for line in self:
            if line.id and (line.account_id.reconcile or line.account_id.account_type in ('asset_cash', 'liability_credit_card')):
                if line.reconciled or line.amount_residual == 0:
                    line.amount_residual_usd = 0.0
                else:
                    reconciled_balance = sum(line.matched_credit_ids.mapped('amount_usd')) \
                                         - sum(line.matched_debit_ids.mapped('amount_usd'))

                    line.amount_residual_usd = (line.debit_usd - line.credit_usd) - reconciled_balance

                line.reconciled = (line.amount_residual_usd == 0 or line.amount_residual == 0)
            else:
                # Must not have any reconciliation since the line is not eligible for that.
                line.amount_residual_usd = 0.0
                line.reconciled = False

    def reconcile(self):
        """Reconciliacion con sincronizacion de `amount_usd` en los parciales.

        Pachacutec/Sefinca - Este metodo era una COPIA LITERAL del
        `account.move.line.reconcile()` de Odoo 18 (~276 lineas), con el codigo
        propio de LocVe anadido al final. v302 - La copia se elimino y se delega en
        `super()`:

        * La copia arrastraba la validacion de v18, MAS ESTRICTA que la de v20, y
          bloqueaba el cierre de sesion con
          `UserError: Account Cash Difference Gain does not allow reconciliation`
          (una cuenta de diferencia de caja, tipo `income`, nunca reconcilia; el
          core de v20 no la manda por `reconcile()`).
        * Contenia `self.env.cr.commit()` DENTRO del metodo de negocio. Rompe la
          atomicidad: los savepoints de los callers (p.ej. el cron
          `_launch_cron_generate_invoice_period`) dejan de proteger y un error
          posterior deja parciales escritos a medias. La transaccion la maneja el
          caller, nunca el metodo.
        * Dejaba `print()` de depuracion en produccion.

        Se conserva integra la logica propia de LocVe: el reparto secuencial de
        `amount_usd` entre los `account.partial.reconcile` nuevos, para que los
        conciliados en USD de Sefinca/Innovo cuadren con `debit_usd`/`credit_usd`.
        """
        # v302 - El `reconcile()` del core de v20 ya NO devuelve diccionario
        # (en v18 devolvia {'partials', 'exchange_partials', ...}); devuelve
        # None. El valor de retorno se conserva por si el core lo restaura, pero
        # los parciales se obtienen por DIFERENCIA: se fotografian los
        # `matched_*` de antes y se calcula lo que la conciliacion anadio.
        #
        # Sin esto, `results` era siempre `{}` y el reparto secuencial de
        # `amount_usd` no se ejecutaba NUNCA, con lo que todos los
        # `account.partial.reconcile` quedaban en `amount_usd = 0` (su valor por
        # defecto) y `amount_residual_usd` no descontaba lo conciliado.
        self.flush_recordset()
        partials_before = self.matched_debit_ids | self.matched_credit_ids
        results = super().reconcile() or {}
        self.invalidate_recordset(['matched_debit_ids', 'matched_credit_ids'])
        partials = (self.matched_debit_ids | self.matched_credit_ids) - partials_before
        partials = partials.sorted('id')
        if not partials and isinstance(results, dict) and results.get('partials'):
            partials = results['partials'].sorted('id')

        # --- LocVe: sincronizacion secuencial de amount_usd en los parciales ---
        not_paid_invoices = self.move_id.filtered(
            lambda move: move.is_invoice(include_receipts=True)
            and move.payment_state not in ('paid', 'in_payment')
        )
        not_paid_invoices.filtered(
            lambda move: move.payment_state in ('paid', 'in_payment')
        )._invoice_paid_hook()

        new_partial_ids = set(partials.ids)
        remaining_usd = {}
        for partial in partials:
            debit = partial.debit_move_id
            credit = partial.credit_move_id

            if debit not in remaining_usd:
                already = sum(
                    other.amount_usd for other in debit.matched_credit_ids
                    if other.id not in new_partial_ids
                )
                remaining_usd[debit] = max(0.0, (debit.debit_usd or 0.0) - already)

            if credit not in remaining_usd:
                already = sum(
                    other.amount_usd for other in credit.matched_debit_ids
                    if other.id not in new_partial_ids
                )
                remaining_usd[credit] = max(0.0, (credit.credit_usd or 0.0) - already)

            amount_usd = min(remaining_usd[debit], remaining_usd[credit])
            remaining_usd[debit] -= amount_usd
            remaining_usd[credit] -= amount_usd

            partial.write({'amount_usd': amount_usd})

        # v308 - `amount_residual_usd` depende de `matched_debit_ids` /
        # `matched_credit_ids`, pero NO de `amount_usd`, que es justo lo que
        # escribe el reparto anterior. El valor almacenado queda obsoleto: tras
        # una conciliacion en doble moneda la linea seguia mostrando el residual
        # integro (una retencion IGTF de 34,80 USD sobre una factura de 1.160
        # dejaba `amount_residual_usd = 1160.00` en vez de 1125.20). Tambien
        # queda obsoleto el flag `reconciled`, que se asigna dentro de ese mismo
        # compute. Se recomputa aqui, punto unico por el que pasan TODAS las
        # conciliaciones del modulo, en vez de parchear cada wizard.
        touched = partials.mapped('debit_move_id') | partials.mapped('credit_move_id')
        (self | touched)._compute_amount_residual_usd()

        return results

    @api.model
    def _prepare_reconciliation_single_partial(self, debit_vals, credit_vals, shadowed_aml_values=None):
        """ Prepare the values to create an account.partial.reconcile later when reconciling the dictionaries passed
        as parameters, each one representing an account.move.line.
        :param debit_vals:  The values of account.move.line to consider for a debit line.
        :param credit_vals: The values of account.move.line to consider for a credit line.
        :param shadowed_aml_values: A mapping aml -> dictionary to replace some original aml values to something else.
        :return:            A dictionary:
            * debit_vals:   None if the line has nothing left to reconcile.
            * credit_vals:  None if the line has nothing left to reconcile.
            * partial_values: The newly computed values for the partial.
        """
        # agregar variable al contexto para que no se cree el exchange

        def get_aml(vals):
            # Odoo 20 usa la clave 'aml'; las firmas heredadas usaban 'record'.
            return vals.get('aml') or vals.get('record') or self.env['account.move.line']

        def get_val(vals, field, default=None):
            aml = get_aml(vals)
            if aml:
                return aml._get_reconciliation_aml_field_value(field, shadowed_aml_values)
            return vals.get(field, default)

        debit_aml = get_aml(debit_vals)
        credit_aml = get_aml(credit_vals)
        debit_currency = get_val(debit_vals, 'currency_id')
        credit_currency = get_val(credit_vals, 'currency_id')
        company_currency = debit_aml.company_currency_id

        def get_odoo_rate(vals):
            aml = get_aml(vals)
            if aml and aml.move_id.is_invoice(include_receipts=True):
                exchange_rate_date = aml.move_id.invoice_date
            else:
                exchange_rate_date = get_val(vals, 'date', fields.Date.today())
            company = aml.company_id if aml else vals.get('company')
            to_re = recon_currency._get_conversion_rate(company_currency, recon_currency, company,
                                                        exchange_rate_date)
            tax_today = aml.move_id.tax_today if aml and hasattr(aml.move_id, 'tax_today') else 0.0
            # v308 - Esta tasa convierte de MONEDA DE COMPANIA a `recon_currency`:
            # el que la consume hace
            # `recon_debit_amount = recon_currency.round(remaining_debit_amount * debit_rate)`
            # partiendo de un importe en moneda de compania. Por eso vale
            # `tax_today` ("moneda alterna por 1 unidad de base", ver
            # `_compute_tax_today`) y NO `1 / tax_today`, que es el
            # `inverse_rate` del core: la inversion que v306 corrigio en todo el
            # modulo y que aqui seguia viva.
            # Con la base al reves, una factura de 1.160 USD se reconocia como
            # 1,35 VES en vez de 995.149,63 VES; `partial_amount` salia 0, el
            # parcial se creaba con `amount = 0` y los 1.160 USD enteros se
            # contabilizaban como diferencia de cambio (`debit_exchange_amount =
            # remaining_debit_amount - partial_amount`), conciliandose contra la
            # factura y dejandola marcada como PAGADA.
            # `tax_today` solo es aplicable cuando `recon_currency` es de verdad
            # la moneda alterna de la compania. Para cualquier otra moneda
            # (p. ej. una factura en euros en una compania cuya alterna es VES)
            # se usa la conversion publicada por Odoo, `to_re`.
            alterna = company.currency_id_dif if company else self.env.company.currency_id_dif
            if tax_today > 0 and alterna and recon_currency and recon_currency == alterna:
                return tax_today
            if to_re:
                return to_re
            return 1 / tax_today if tax_today > 0 else 1

        def get_accounting_rate(vals):
            aml = get_aml(vals)
            currency = get_val(vals, 'currency_id') if aml else vals.get('currency')
            balance = get_val(vals, 'balance', 0.0) if aml else vals.get('balance', 0.0)
            amount_currency = get_val(vals, 'amount_currency', 0.0) if aml else vals.get('amount_currency', 0.0)
            if company_currency.is_zero(balance) or (currency and currency.is_zero(amount_currency)):
                return None
            else:
                return abs(amount_currency) / abs(balance)

        res = {
            'debit_values': debit_vals,
            'credit_values': credit_vals,
            'debit_aml': debit_aml,
            'credit_aml': credit_aml,
        }
        remaining_debit_amount_curr = debit_vals['amount_residual_currency']
        remaining_credit_amount_curr = credit_vals['amount_residual_currency']
        remaining_debit_amount = debit_vals['amount_residual']
        remaining_credit_amount = credit_vals['amount_residual']

        has_debit_zero_residual = company_currency.is_zero(remaining_debit_amount)
        has_credit_zero_residual = company_currency.is_zero(remaining_credit_amount)
        has_debit_zero_residual_currency = debit_currency.is_zero(remaining_debit_amount_curr)
        has_credit_zero_residual_currency = credit_currency.is_zero(remaining_credit_amount_curr)
        debit_account_type = debit_aml.account_id.account_type if debit_aml else None
        is_rec_pay_account = debit_account_type in ('asset_receivable', 'liability_payable')

        if debit_currency == credit_currency == company_currency and not has_debit_zero_residual and not has_credit_zero_residual:
            recon_currency = company_currency
            debit_rate = credit_rate = 1.0
            recon_debit_amount = remaining_debit_amount
            recon_credit_amount = -remaining_credit_amount
        elif debit_currency == company_currency and is_rec_pay_account and not has_debit_zero_residual and credit_currency != company_currency and not has_credit_zero_residual_currency:
            recon_currency = credit_currency
            debit_rate = get_odoo_rate(debit_vals)
            credit_rate = get_accounting_rate(credit_vals)
            recon_debit_amount = recon_currency.round(remaining_debit_amount * debit_rate)
            recon_credit_amount = -remaining_credit_amount_curr
        elif debit_currency != company_currency and is_rec_pay_account and not has_debit_zero_residual_currency and credit_currency == company_currency and not has_credit_zero_residual:
            recon_currency = debit_currency
            debit_rate = get_accounting_rate(debit_vals)
            credit_rate = get_odoo_rate(credit_vals)
            recon_debit_amount = remaining_debit_amount_curr
            recon_credit_amount = recon_currency.round(-remaining_credit_amount * credit_rate)
        elif debit_currency == credit_currency and debit_currency != company_currency and not has_debit_zero_residual_currency and not has_credit_zero_residual_currency:
            recon_currency = debit_currency
            debit_rate = get_accounting_rate(debit_vals)
            credit_rate = get_accounting_rate(credit_vals)
            recon_debit_amount = remaining_debit_amount_curr
            recon_credit_amount = -remaining_credit_amount_curr
        elif debit_currency == credit_currency and debit_currency != company_currency and (has_debit_zero_residual_currency or has_credit_zero_residual_currency):
            recon_currency = company_currency
            debit_rate = None
            credit_rate = None
            recon_debit_amount = remaining_debit_amount
            recon_credit_amount = -remaining_credit_amount
        else:
            recon_currency = company_currency
            debit_rate = get_accounting_rate(debit_vals)
            credit_rate = get_accounting_rate(credit_vals)
            recon_debit_amount = remaining_debit_amount
            recon_credit_amount = -remaining_credit_amount

        skip_reconciliation = False
        if recon_currency.is_zero(recon_debit_amount):
            res['debit_values'] = None
            skip_reconciliation = True
        if recon_currency.is_zero(recon_credit_amount):
            res['credit_values'] = None
            skip_reconciliation = True
        if skip_reconciliation:
            return res

        compare_amounts = recon_currency.compare_amounts(recon_debit_amount, recon_credit_amount)
        min_recon_amount = min(recon_debit_amount, recon_credit_amount)
        debit_fully_matched = compare_amounts <= 0
        credit_fully_matched = compare_amounts >= 0

        if recon_currency == company_currency:
            partial_amount = min_recon_amount
            if debit_rate:
                partial_debit_amount_currency = debit_currency.round(debit_rate * min_recon_amount)
                partial_debit_amount_currency = min(partial_debit_amount_currency, remaining_debit_amount_curr)
            else:
                partial_debit_amount_currency = 0.0
            if credit_rate:
                partial_credit_amount_currency = credit_currency.round(credit_rate * min_recon_amount)
                partial_credit_amount_currency = min(partial_credit_amount_currency, -remaining_credit_amount_curr)
            else:
                partial_credit_amount_currency = 0.0
        else:
            if debit_rate:
                partial_debit_amount = company_currency.round(min_recon_amount / debit_rate)
                partial_debit_amount = min(partial_debit_amount, remaining_debit_amount)
            else:
                partial_debit_amount = 0.0
            if credit_rate:
                partial_credit_amount = company_currency.round(min_recon_amount / credit_rate)
                partial_credit_amount = min(partial_credit_amount, -remaining_credit_amount)
            else:
                partial_credit_amount = 0.0
            partial_amount = min(partial_debit_amount, partial_credit_amount)

            if debit_currency == company_currency:
                partial_debit_amount_currency = partial_amount
            else:
                partial_debit_amount_currency = min_recon_amount
            if credit_currency == company_currency:
                partial_credit_amount_currency = partial_amount
            else:
                partial_credit_amount_currency = min_recon_amount

        if not self._context.get('no_exchange_difference'):
            exchange_lines_to_fix = self.env['account.move.line']
            amounts_list = []
            if recon_currency == company_currency:
                if debit_fully_matched:
                    debit_exchange_amount = remaining_debit_amount_curr - partial_debit_amount_currency
                    if not debit_currency.is_zero(debit_exchange_amount):
                        if debit_aml:
                            exchange_lines_to_fix += debit_aml
                        amounts_list.append({'amount_residual_currency': debit_exchange_amount})
                        remaining_debit_amount_curr -= debit_exchange_amount
                if credit_fully_matched:
                    credit_exchange_amount = remaining_credit_amount_curr + partial_credit_amount_currency
                    if not credit_currency.is_zero(credit_exchange_amount):
                        if credit_aml:
                            exchange_lines_to_fix += credit_aml
                        amounts_list.append({'amount_residual_currency': credit_exchange_amount})
                        remaining_credit_amount_curr += credit_exchange_amount
            else:
                if debit_fully_matched:
                    debit_exchange_amount = remaining_debit_amount - partial_amount
                    if not company_currency.is_zero(debit_exchange_amount):
                        if debit_aml:
                            exchange_lines_to_fix += debit_aml
                        amounts_list.append({'amount_residual': debit_exchange_amount})
                        remaining_debit_amount -= debit_exchange_amount
                        if debit_currency == company_currency:
                            remaining_debit_amount_curr -= debit_exchange_amount
                else:
                    debit_exchange_amount = partial_debit_amount - partial_amount
                    if company_currency.compare_amounts(debit_exchange_amount, 0.0) > 0:
                        if debit_aml:
                            exchange_lines_to_fix += debit_aml
                        amounts_list.append({'amount_residual': debit_exchange_amount})
                        remaining_debit_amount -= debit_exchange_amount
                        if debit_currency == company_currency:
                            remaining_debit_amount_curr -= debit_exchange_amount
                if credit_fully_matched:
                    credit_exchange_amount = remaining_credit_amount + partial_amount
                    if not company_currency.is_zero(credit_exchange_amount):
                        if credit_aml:
                            exchange_lines_to_fix += credit_aml
                        amounts_list.append({'amount_residual': credit_exchange_amount})
                        remaining_credit_amount += credit_exchange_amount
                        if credit_currency == company_currency:
                            remaining_credit_amount_curr -= credit_exchange_amount
                else:
                    credit_exchange_amount = partial_amount - partial_credit_amount
                    if company_currency.compare_amounts(credit_exchange_amount, 0.0) < 0:
                        if credit_aml:
                            exchange_lines_to_fix += credit_aml
                        amounts_list.append({'amount_residual': credit_exchange_amount})
                        remaining_credit_amount += credit_exchange_amount
                        if credit_currency == company_currency:
                            remaining_credit_amount_curr -= credit_exchange_amount
            if exchange_lines_to_fix:
                res['exchange_values'] = exchange_lines_to_fix._prepare_exchange_difference_move_vals(
                    amounts_list,
                    exchange_date=max(
                        debit_aml._get_reconciliation_aml_field_value('date', shadowed_aml_values) if debit_aml else get_val(debit_vals, 'date'),
                        credit_aml._get_reconciliation_aml_field_value('date', shadowed_aml_values) if credit_aml else get_val(credit_vals, 'date'),
                    ),
                )
                res['exchange_values']['to_post'] = (
                    debit_aml.parent_state == 'posted' and credit_aml.parent_state == 'posted'
                ) if debit_aml and credit_aml else False

        remaining_debit_amount -= partial_amount
        remaining_credit_amount += partial_amount
        remaining_debit_amount_curr -= partial_debit_amount_currency
        remaining_credit_amount_curr += partial_credit_amount_currency

        res['partial_values'] = {
            'amount': partial_amount,
            'debit_amount_currency': partial_debit_amount_currency,
            'credit_amount_currency': partial_credit_amount_currency,
            'debit_move_id': debit_aml.id if debit_aml else None,
            'credit_move_id': credit_aml.id if credit_aml else None,
        }

        debit_vals['amount_residual'] = remaining_debit_amount
        debit_vals['amount_residual_currency'] = remaining_debit_amount_curr
        credit_vals['amount_residual'] = remaining_credit_amount
        credit_vals['amount_residual_currency'] = remaining_credit_amount_curr

        if (debit_currency.is_zero(debit_vals['amount_residual_currency'])
                and company_currency.is_zero(debit_vals['amount_residual'])):
            res['debit_values'] = None
        if (credit_currency.is_zero(credit_vals['amount_residual_currency'])
                and company_currency.is_zero(credit_vals['amount_residual'])):
            res['credit_values'] = None
        return res


        compare_amounts = recon_currency.compare_amounts(recon_debit_amount, recon_credit_amount)
        min_recon_amount = min(recon_debit_amount, recon_credit_amount)
        debit_fully_matched = compare_amounts <= 0
        credit_fully_matched = compare_amounts >= 0

        if recon_currency == company_currency:
            partial_amount = min_recon_amount
            if debit_rate:
                partial_debit_amount_currency = debit_vals['currency'].round(debit_rate * min_recon_amount)
                partial_debit_amount_currency = min(partial_debit_amount_currency, remaining_debit_amount_curr)
            else:
                partial_debit_amount_currency = 0.0
            if credit_rate:
                partial_credit_amount_currency = credit_vals['currency'].round(credit_rate * min_recon_amount)
                partial_credit_amount_currency = min(partial_credit_amount_currency, -remaining_credit_amount_curr)
            else:
                partial_credit_amount_currency = 0.0
        else:
            if debit_rate:
                partial_debit_amount = company_currency.round(min_recon_amount / debit_rate)
                partial_debit_amount = min(partial_debit_amount, remaining_debit_amount)
            else:
                partial_debit_amount = 0.0
            if credit_rate:
                partial_credit_amount = company_currency.round(min_recon_amount / credit_rate)
                partial_credit_amount = min(partial_credit_amount, -remaining_credit_amount)
            else:
                partial_credit_amount = 0.0
            partial_amount = min(partial_debit_amount, partial_credit_amount)

            if debit_vals['currency'] == company_currency:
                partial_debit_amount_currency = partial_amount
            else:
                partial_debit_amount_currency = min_recon_amount
            if credit_vals['currency'] == company_currency:
                partial_credit_amount_currency = partial_amount
            else:
                partial_credit_amount_currency = min_recon_amount

        if not self._context.get('no_exchange_difference'):
            exchange_lines_to_fix = self.env['account.move.line']
            amounts_list = []
            if recon_currency == company_currency:
                if debit_fully_matched:
                    debit_exchange_amount = remaining_debit_amount_curr - partial_debit_amount_currency
                    if not debit_vals['currency'].is_zero(debit_exchange_amount):
                        if debit_vals.get('record'):
                            exchange_lines_to_fix += debit_vals['record']
                        amounts_list.append({'amount_residual_currency': debit_exchange_amount})
                        remaining_debit_amount_curr -= debit_exchange_amount
                if credit_fully_matched:
                    credit_exchange_amount = remaining_credit_amount_curr + partial_credit_amount_currency
                    if not credit_vals['currency'].is_zero(credit_exchange_amount):
                        if credit_vals.get('record'):
                            exchange_lines_to_fix += credit_vals['record']
                        amounts_list.append({'amount_residual_currency': credit_exchange_amount})
                        remaining_credit_amount_curr += credit_exchange_amount
            else:
                if debit_fully_matched:
                    debit_exchange_amount = remaining_debit_amount - partial_amount
                    if not company_currency.is_zero(debit_exchange_amount):
                        if debit_vals.get('record'):
                            exchange_lines_to_fix += debit_vals['record']
                        amounts_list.append({'amount_residual': debit_exchange_amount})
                        remaining_debit_amount -= debit_exchange_amount
                        if debit_vals['currency'] == company_currency:
                            remaining_debit_amount_curr -= debit_exchange_amount
                else:
                    debit_exchange_amount = partial_debit_amount - partial_amount
                    if company_currency.compare_amounts(debit_exchange_amount, 0.0) > 0:
                        if debit_vals.get('record'):
                            exchange_lines_to_fix += debit_vals['record']
                        amounts_list.append({'amount_residual': debit_exchange_amount})
                        remaining_debit_amount -= debit_exchange_amount
                        if debit_vals['currency'] == company_currency:
                            remaining_debit_amount_curr -= debit_exchange_amount
                if credit_fully_matched:
                    credit_exchange_amount = remaining_credit_amount + partial_amount
                    if not company_currency.is_zero(credit_exchange_amount):
                        if credit_vals.get('record'):
                            exchange_lines_to_fix += credit_vals['record']
                        amounts_list.append({'amount_residual': credit_exchange_amount})
                        remaining_credit_amount += credit_exchange_amount
                        if credit_vals['currency'] == company_currency:
                            remaining_credit_amount_curr -= credit_exchange_amount
                else:
                    credit_exchange_amount = partial_amount - partial_credit_amount
                    if company_currency.compare_amounts(credit_exchange_amount, 0.0) < 0:
                        if credit_vals.get('record'):
                            exchange_lines_to_fix += credit_vals['record']
                        amounts_list.append({'amount_residual': credit_exchange_amount})
                        remaining_credit_amount -= credit_exchange_amount
                        if credit_vals['currency'] == company_currency:
                            remaining_credit_amount_curr -= credit_exchange_amount
            if exchange_lines_to_fix:
                res['exchange_vals'] = exchange_lines_to_fix._prepare_exchange_difference_move_vals(
                    amounts_list,
                    exchange_date=max(debit_vals['date'], credit_vals['date']),
                )

        remaining_debit_amount -= partial_amount
        remaining_credit_amount += partial_amount
        remaining_debit_amount_curr -= partial_debit_amount_currency
        remaining_credit_amount_curr += partial_credit_amount_currency

        res['partial_vals'] = {
            'amount': partial_amount,
            'debit_amount_currency': partial_debit_amount_currency,
            'credit_amount_currency': partial_credit_amount_currency,
            'debit_move_id': debit_vals.get('record') and debit_vals['record'].id,
            'credit_move_id': credit_vals.get('record') and credit_vals['record'].id,
        }

        debit_vals['amount_residual'] = remaining_debit_amount
        debit_vals['amount_residual_currency'] = remaining_debit_amount_curr
        credit_vals['amount_residual'] = remaining_credit_amount
        credit_vals['amount_residual_currency'] = remaining_credit_amount_curr

        if debit_fully_matched:
            res['debit_vals'] = None
        if credit_fully_matched:
            res['credit_vals'] = None
        return res


        compare_amounts = recon_currency.compare_amounts(recon_debit_amount, recon_credit_amount)
        min_recon_amount = min(recon_debit_amount, recon_credit_amount)
        debit_fully_matched = compare_amounts <= 0
        credit_fully_matched = compare_amounts >= 0

        if recon_currency == company_currency:
            partial_amount = min_recon_amount
            if debit_rate:
                partial_debit_amount_currency = debit_vals['currency'].round(debit_rate * min_recon_amount)
                partial_debit_amount_currency = min(partial_debit_amount_currency, remaining_debit_amount_curr)
            else:
                partial_debit_amount_currency = 0.0
            if credit_rate:
                partial_credit_amount_currency = credit_vals['currency'].round(credit_rate * min_recon_amount)
                partial_credit_amount_currency = min(partial_credit_amount_currency, -remaining_credit_amount_curr)
            else:
                partial_credit_amount_currency = 0.0
        else:
            if debit_rate:
                partial_debit_amount = company_currency.round(min_recon_amount / debit_rate)
                partial_debit_amount = min(partial_debit_amount, remaining_debit_amount)
            else:
                partial_debit_amount = 0.0
            if credit_rate:
                partial_credit_amount = company_currency.round(min_recon_amount / credit_rate)
                partial_credit_amount = min(partial_credit_amount, -remaining_credit_amount)
            else:
                partial_credit_amount = 0.0
            partial_amount = min(partial_debit_amount, partial_credit_amount)

            if debit_vals['currency'] == company_currency:
                partial_debit_amount_currency = partial_amount
            else:
                partial_debit_amount_currency = min_recon_amount
            if credit_vals['currency'] == company_currency:
                partial_credit_amount_currency = partial_amount
            else:
                partial_credit_amount_currency = min_recon_amount

        if not self._context.get('no_exchange_difference'):
            exchange_lines_to_fix = self.env['account.move.line']
            amounts_list = []
            if recon_currency == company_currency:
                if debit_fully_matched:
                    debit_exchange_amount = remaining_debit_amount_curr - partial_debit_amount_currency
                    if not debit_vals['currency'].is_zero(debit_exchange_amount):
                        if debit_vals.get('record'):
                            exchange_lines_to_fix += debit_vals['record']
                        amounts_list.append({'amount_residual_currency': debit_exchange_amount})
                        remaining_debit_amount_curr -= debit_exchange_amount
                if credit_fully_matched:
                    credit_exchange_amount = remaining_credit_amount_curr + partial_credit_amount_currency
                    if not credit_vals['currency'].is_zero(credit_exchange_amount):
                        if credit_vals.get('record'):
                            exchange_lines_to_fix += credit_vals['record']
                        amounts_list.append({'amount_residual_currency': credit_exchange_amount})
                        remaining_credit_amount_curr += credit_exchange_amount
            else:
                if debit_fully_matched:
                    debit_exchange_amount = remaining_debit_amount - partial_amount
                    if not company_currency.is_zero(debit_exchange_amount):
                        if debit_vals.get('record'):
                            exchange_lines_to_fix += debit_vals['record']
                        amounts_list.append({'amount_residual': debit_exchange_amount})
                        remaining_debit_amount -= debit_exchange_amount
                        if debit_vals['currency'] == company_currency:
                            remaining_debit_amount_curr -= debit_exchange_amount
                else:
                    debit_exchange_amount = partial_debit_amount - partial_amount
                    if company_currency.compare_amounts(debit_exchange_amount, 0.0) > 0:
                        if debit_vals.get('record'):
                            exchange_lines_to_fix += debit_vals['record']
                        amounts_list.append({'amount_residual': debit_exchange_amount})
                        remaining_debit_amount -= debit_exchange_amount
                        if debit_vals['currency'] == company_currency:
                            remaining_debit_amount_curr -= debit_exchange_amount
                if credit_fully_matched:
                    credit_exchange_amount = remaining_credit_amount + partial_amount
                    if not company_currency.is_zero(credit_exchange_amount):
                        if credit_vals.get('record'):
                            exchange_lines_to_fix += credit_vals['record']
                        amounts_list.append({'amount_residual': credit_exchange_amount})
                        remaining_credit_amount += credit_exchange_amount
                        if credit_vals['currency'] == company_currency:
                            remaining_credit_amount_curr -= credit_exchange_amount
                else:
                    credit_exchange_amount = partial_amount - partial_credit_amount
                    if company_currency.compare_amounts(credit_exchange_amount, 0.0) < 0:
                        if credit_vals.get('record'):
                            exchange_lines_to_fix += credit_vals['record']
                        amounts_list.append({'amount_residual': credit_exchange_amount})
                        remaining_credit_amount -= credit_exchange_amount
                        if credit_vals['currency'] == company_currency:
                            remaining_credit_amount_curr -= credit_exchange_amount
            if exchange_lines_to_fix:
                res['exchange_vals'] = exchange_lines_to_fix._prepare_exchange_difference_move_vals(
                    amounts_list,
                    exchange_date=max(debit_vals['date'], credit_vals['date']),
                )

        remaining_debit_amount -= partial_amount
        remaining_credit_amount += partial_amount
        remaining_debit_amount_curr -= partial_debit_amount_currency
        remaining_credit_amount_curr += partial_credit_amount_currency

        res['partial_vals'] = {
            'amount': partial_amount,
            'debit_amount_currency': partial_debit_amount_currency,
            'credit_amount_currency': partial_credit_amount_currency,
            'debit_move_id': debit_vals.get('record') and debit_vals['record'].id,
            'credit_move_id': credit_vals.get('record') and credit_vals['record'].id,
        }

        debit_vals['amount_residual'] = remaining_debit_amount
        debit_vals['amount_residual_currency'] = remaining_debit_amount_curr
        credit_vals['amount_residual'] = remaining_credit_amount
        credit_vals['amount_residual_currency'] = remaining_credit_amount_curr

        if debit_fully_matched:
            res['debit_vals'] = None
        if credit_fully_matched:
            res['credit_vals'] = None
        return res


        # ==== Match both lines together and compute amounts to reconcile ====

        # Determine which line is fully matched by the other.
        compare_amounts = recon_currency.compare_amounts(recon_debit_amount, recon_credit_amount)
        min_recon_amount = min(recon_debit_amount, recon_credit_amount)
        debit_fully_matched = compare_amounts <= 0
        credit_fully_matched = compare_amounts >= 0

        # ==== Computation of partial amounts ====
        if recon_currency == company_currency:
            # Compute the partial amount expressed in company currency.
            partial_amount = min_recon_amount

            # Compute the partial amount expressed in foreign currency.
            if debit_rate:
                partial_debit_amount_currency = debit_vals['currency'].round(debit_rate * min_recon_amount)
                partial_debit_amount_currency = min(partial_debit_amount_currency, remaining_debit_amount_curr)
            else:
                partial_debit_amount_currency = 0.0
            if credit_rate:
                partial_credit_amount_currency = credit_vals['currency'].round(credit_rate * min_recon_amount)
                partial_credit_amount_currency = min(partial_credit_amount_currency, -remaining_credit_amount_curr)
            else:
                partial_credit_amount_currency = 0.0

        else:
            # recon_currency != company_currency
            # Compute the partial amount expressed in company currency.
            if debit_rate:
                partial_debit_amount = company_currency.round(min_recon_amount / debit_rate)
                partial_debit_amount = min(partial_debit_amount, remaining_debit_amount)
            else:
                partial_debit_amount = 0.0
            if credit_rate:
                partial_credit_amount = company_currency.round(min_recon_amount / credit_rate)
                partial_credit_amount = min(partial_credit_amount, -remaining_credit_amount)
            else:
                partial_credit_amount = 0.0
            partial_amount = min(partial_debit_amount, partial_credit_amount)

            # Compute the partial amount expressed in foreign currency.
            # Take care to handle the case when a line expressed in company currency is mimicking the foreign
            # currency of the opposite line.
            if debit_vals['currency'] == company_currency:
                partial_debit_amount_currency = partial_amount
            else:
                partial_debit_amount_currency = min_recon_amount
            if credit_vals['currency'] == company_currency:
                partial_credit_amount_currency = partial_amount
            else:
                partial_credit_amount_currency = min_recon_amount

        # Computation of the partial exchange difference. You can skip this part using the
        # `no_exchange_difference` context key (when reconciling an exchange difference for example).
        if not self._context.get('no_exchange_difference'):
            exchange_lines_to_fix = self.env['account.move.line']
            amounts_list = []
            if recon_currency == company_currency:
                if debit_fully_matched:
                    debit_exchange_amount = remaining_debit_amount_curr - partial_debit_amount_currency
                    if not debit_vals['currency'].is_zero(debit_exchange_amount):
                        if debit_vals.get('record'):
                            exchange_lines_to_fix += debit_vals['record']
                        amounts_list.append({'amount_residual_currency': debit_exchange_amount})
                        remaining_debit_amount_curr -= debit_exchange_amount
                if credit_fully_matched:
                    credit_exchange_amount = remaining_credit_amount_curr + partial_credit_amount_currency
                    if not credit_vals['currency'].is_zero(credit_exchange_amount):
                        if credit_vals.get('record'):
                            exchange_lines_to_fix += credit_vals['record']
                        amounts_list.append({'amount_residual_currency': credit_exchange_amount})
                        remaining_credit_amount_curr += credit_exchange_amount

            else:
                if debit_fully_matched:
                    # Create an exchange difference on the remaining amount expressed in company's currency.
                    debit_exchange_amount = remaining_debit_amount - partial_amount
                    if not company_currency.is_zero(debit_exchange_amount):
                        if debit_vals.get('record'):
                            exchange_lines_to_fix += debit_vals['record']
                        amounts_list.append({'amount_residual': debit_exchange_amount})
                        remaining_debit_amount -= debit_exchange_amount
                        if debit_vals['currency'] == company_currency:
                            remaining_debit_amount_curr -= debit_exchange_amount
                else:
                    # Create an exchange difference ensuring the rate between the residual amounts expressed in
                    # both foreign and company's currency is still consistent regarding the rate between
                    # 'amount_currency' & 'balance'.
                    debit_exchange_amount = partial_debit_amount - partial_amount
                    if company_currency.compare_amounts(debit_exchange_amount, 0.0) > 0:
                        if debit_vals.get('record'):
                            exchange_lines_to_fix += debit_vals['record']
                        amounts_list.append({'amount_residual': debit_exchange_amount})
                        remaining_debit_amount -= debit_exchange_amount
                        if debit_vals['currency'] == company_currency:
                            remaining_debit_amount_curr -= debit_exchange_amount

                if credit_fully_matched:
                    # Create an exchange difference on the remaining amount expressed in company's currency.
                    credit_exchange_amount = remaining_credit_amount + partial_amount
                    if not company_currency.is_zero(credit_exchange_amount):
                        if credit_vals.get('record'):
                            exchange_lines_to_fix += credit_vals['record']
                        amounts_list.append({'amount_residual': credit_exchange_amount})
                        remaining_credit_amount += credit_exchange_amount
                        if credit_vals['currency'] == company_currency:
                            remaining_credit_amount_curr -= credit_exchange_amount
                else:
                    # Create an exchange difference ensuring the rate between the residual amounts expressed in
                    # both foreign and company's currency is still consistent regarding the rate between
                    # 'amount_currency' & 'balance'.
                    credit_exchange_amount = partial_amount - partial_credit_amount
                    if company_currency.compare_amounts(credit_exchange_amount, 0.0) < 0:
                        if credit_vals.get('record'):
                            exchange_lines_to_fix += credit_vals['record']
                        amounts_list.append({'amount_residual': credit_exchange_amount})
                        remaining_credit_amount -= credit_exchange_amount
                        if credit_vals['currency'] == company_currency:
                            remaining_credit_amount_curr -= credit_exchange_amount

            if exchange_lines_to_fix:
                res['exchange_vals'] = exchange_lines_to_fix._prepare_exchange_difference_move_vals(
                    amounts_list,
                    exchange_date=max(debit_vals['date'], credit_vals['date']),
                )

        # ==== Create partials ====

        remaining_debit_amount -= partial_amount
        remaining_credit_amount += partial_amount
        remaining_debit_amount_curr -= partial_debit_amount_currency
        remaining_credit_amount_curr += partial_credit_amount_currency

        res['partial_vals'] = {
            'amount': partial_amount,
            'debit_amount_currency': partial_debit_amount_currency,
            'credit_amount_currency': partial_credit_amount_currency,
            'debit_move_id': debit_vals.get('record') and debit_vals['record'].id,
            'credit_move_id': credit_vals.get('record') and credit_vals['record'].id,
        }

        debit_vals['amount_residual'] = remaining_debit_amount
        debit_vals['amount_residual_currency'] = remaining_debit_amount_curr
        credit_vals['amount_residual'] = remaining_credit_amount
        credit_vals['amount_residual_currency'] = remaining_credit_amount_curr

        if debit_fully_matched:
            res['debit_vals'] = None
        if credit_fully_matched:
            res['credit_vals'] = None
        return res

    # Odoo 20 elimino tanto '_apply_price_difference' como
    # '_generate_price_difference_vals' (procedian de stock_account) y los
    # sustituyo por los ajustes de 'product.value'. Este override queda sin
    # contraparte en el core y se retira junto con la migracion de SVL.
    # BACKUP: _mig_backup_svl/account_move_line.py.bak_svl_refs



    def _create_reconciliation_partials(self):
        '''create the partial reconciliation between all the records in self
         :return: A recordset of account.partial.reconcile.
        '''
        partials_vals_list, exchange_data = self._prepare_reconciliation_partials([
            {
                'aml': line,
                'record': line,
                'balance': line.balance,
                'amount_currency': line.amount_currency,
                'amount_residual': line.amount_residual,
                'amount_residual_currency': line.amount_residual_currency,
                'company': line.company_id,
                'currency': line.currency_id,
                'date': line.date,
            }
            for line in self
        ])
        partials = self.env['account.partial.reconcile'].create(partials_vals_list)
        return partials

    @api.model
    def _prepare_reconciliation_partials(self, vals_list):
        ''' Prepare the partials on the current journal items to perform the reconciliation.
        Note: The order of records in self is important because the journal items will be reconciled using this order.
        :return: a tuple of 1) list of vals for partial reconciliation creation, 2) the list of vals for the exchange difference entries to be created
        '''
        exchange_data = {}

        def fix_remaining_cent(currency, abs_residual, partial_amount):
            if abs_residual - currency.rounding <= partial_amount <= abs_residual + currency.rounding:
                return abs_residual
            else:
                return partial_amount

        debit_lines = iter(self.filtered(lambda line: line.balance > 0.0 or line.amount_currency > 0.0 and not line.reconciled))
        credit_lines = iter(self.filtered(lambda line: line.balance < 0.0 or line.amount_currency < 0.0 and not line.reconciled))
        void_lines = iter(self.filtered(lambda line: not line.balance and not line.amount_currency and not line.reconciled))
        debit_line = None
        credit_line = None

        debit_amount_residual = 0.0
        debit_amount_residual_currency = 0.0
        credit_amount_residual = 0.0
        credit_amount_residual_currency = 0.0
        debit_line_currency = None
        credit_line_currency = None

        partials_vals_list = []

        while True:
            if not debit_line:
                debit_line = next(debit_lines, None) or next(void_lines, None)
                if not debit_line:
                    break
                debit_amount_residual = debit_line.amount_residual
                if debit_line.currency_id:
                    debit_amount_residual_currency = debit_line.amount_residual_currency
                    debit_line_currency = debit_line.currency_id
                else:
                    debit_amount_residual_currency = debit_amount_residual
                    debit_line_currency = debit_line.company_currency_id

            if not credit_line:
                credit_line = next(void_lines, None) or next(credit_lines, None)
                if not credit_line:
                    break
                credit_amount_residual = credit_line.amount_residual
                if credit_line.currency_id:
                    credit_amount_residual_currency = credit_line.amount_residual_currency
                    credit_line_currency = credit_line.currency_id
                else:
                    credit_amount_residual_currency = credit_amount_residual
                    credit_line_currency = credit_line.company_currency_id

            min_amount_residual = min(debit_amount_residual, -credit_amount_residual)

            if debit_line_currency == credit_line_currency:
                min_amount_residual_currency = min(debit_amount_residual_currency, -credit_amount_residual_currency)
                min_debit_amount_residual_currency = min_amount_residual_currency
                min_credit_amount_residual_currency = min_amount_residual_currency
            else:
                if credit_line_currency == credit_line.company_currency_id and debit_line_currency == debit_line.company_id.currency_id_dif:
                    min_debit_amount_residual_currency = credit_line.company_currency_id.with_context(
                        tasa_factura=debit_line.tax_today)._convert(
                        min_amount_residual, debit_line.currency_id, credit_line.company_id, credit_line.date)
                    min_debit_amount_residual_currency = abs(min_debit_amount_residual_currency) if debit_amount_residual_currency > 0 else -abs(min_debit_amount_residual_currency)
                    min_credit_amount_residual_currency = debit_line.company_currency_id._convert(
                        min_amount_residual, credit_line.currency_id, debit_line.company_id, debit_line.date)
                    min_credit_amount_residual_currency = abs(min_credit_amount_residual_currency) if credit_amount_residual_currency > 0 else -abs(min_credit_amount_residual_currency)

                elif debit_line_currency == debit_line.company_currency_id and credit_line_currency == credit_line.company_id.currency_id_dif:
                    min_debit_amount_residual_currency = credit_line.company_currency_id._convert(
                        min_amount_residual, debit_line.currency_id, credit_line.company_id, credit_line.date)
                    min_debit_amount_residual_currency = abs(min_debit_amount_residual_currency) if debit_amount_residual_currency > 0 else -abs(min_debit_amount_residual_currency)
                    min_credit_amount_residual_currency = debit_line.company_currency_id.with_context(
                        tasa_factura=credit_line.tax_today)._convert(
                        min_amount_residual, credit_line.currency_id, debit_line.company_id, debit_line.date)
                    min_credit_amount_residual_currency = abs(min_credit_amount_residual_currency) if credit_amount_residual_currency > 0 else -abs(min_credit_amount_residual_currency)
                else:
                    min_debit_amount_residual_currency = credit_line.company_currency_id._convert(
                        min_amount_residual, debit_line.currency_id, credit_line.company_id, credit_line.date)
                    min_credit_amount_residual_currency = debit_line.company_currency_id._convert(
                        min_amount_residual, credit_line.currency_id, debit_line.company_id, debit_line.date)

            debit_amount_residual -= min_amount_residual
            debit_amount_residual_currency -= min_debit_amount_residual_currency
            credit_amount_residual += min_amount_residual
            credit_amount_residual_currency += min_credit_amount_residual_currency

            partials_vals_list.append({
                'amount': min_amount_residual,
                'debit_amount_currency': min_debit_amount_residual_currency,
                'credit_amount_currency': min_credit_amount_residual_currency,
                'debit_move_id': debit_line.id,
                'credit_move_id': credit_line.id,
            })

            has_debit_residual_left = not debit_line.company_currency_id.is_zero(debit_amount_residual) and debit_amount_residual > 0.0
            has_credit_residual_left = not credit_line.company_currency_id.is_zero(credit_amount_residual) and credit_amount_residual < 0.0
            has_debit_residual_curr_left = not debit_line_currency.is_zero(debit_amount_residual_currency) and debit_amount_residual_currency > 0.0
            has_credit_residual_curr_left = not credit_line_currency.is_zero(credit_amount_residual_currency) and credit_amount_residual_currency < 0.0

            if debit_line_currency == credit_line_currency:
                if not has_debit_residual_curr_left and (has_credit_residual_curr_left or not has_debit_residual_left):
                    debit_line = None
                if not has_credit_residual_curr_left and (has_debit_residual_curr_left or not has_debit_residual_left):
                    credit_line = None
            else:
                if not has_debit_residual_left:
                    debit_line = None
                if not has_credit_residual_left:
                    credit_line = None

        return partials_vals_list, exchange_data

    @api.constrains('price_unit', 'discount')
    def _check_price_unit_positive(self):
        for line in self:
            if line.move_id.move_type in ('out_invoice', 'out_refund', 'in_invoice', 'in_refund', 'out_receipt', 'in_receipt'):
                if not line.display_type:
                    if line.price_unit <= 0.0 and line.discount < 100.0:
                        line_name = line.name or (line.product_id and line.product_id.name) or 'Línea de producto'
                        raise ValidationError(_(
                            "Normativa SENIAT (Providencia 0071): No está permitido registrar líneas con Precio Unitario en 0.0 o negativo en '%s'.\n\n"
                            "Si desea entregar un bien o servicio a título gratuito (obsequio, bonificación o muestra sin valor comercial), "
                            "debe ingresar el Precio Unitario de lista de referencia (> 0.0) y aplicar un Descuento del 100%% para cumplir "
                            "con la exigencia fiscal del SENIAT."
                        ) % line_name)

    @api.constrains('tax_ids')
    def _check_single_tax(self):
        for line in self:
            if line.move_id.move_type in ('out_invoice', 'out_refund', 'in_invoice', 'in_refund', 'out_receipt', 'in_receipt'):
                if not line.display_type and len(line.tax_ids) > 1:
                    line_name = line.name or (line.product_id and line.product_id.name) or 'Línea de producto'
                    raise ValidationError(_("No se permite aplicar más de una alícuota de impuesto a la línea '%s'. Para cambiar la alícuota, primero debe remover la anterior.") % line_name)


