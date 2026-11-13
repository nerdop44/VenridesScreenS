from odoo import fields, models, api, _
from datetime import datetime, date, timedelta

class GenerarIgftWizard(models.TransientModel):
    _name = "generar.igtf.wizard"
    _description = "Generar Retención IGTF"

    invoice_id = fields.Many2one('account.move', string='Factura', required=True)
    tax_today = fields.Float(string="Tasa Actual", digits=(16, 4))
    amount = fields.Monetary(currency_field='currency_id_dif', string='Monto $', required=True)
    igtf_porcentage = fields.Float('Porcentaje', required=True, readonly=True)
    igtf_amount = fields.Monetary(currency_field='currency_id_dif', string='Monto IGTF $', required=True, default=0.0,
                                  compute='compute_igtf_amount')
    igtf_amount_bs = fields.Monetary(currency_field='currency_id_company', string='Monto IGTF Bs', required=True,
                                     default=0.0, compute='compute_igtf_amount')
    currency_id_dif = fields.Many2one('res.currency', string='Moneda $', required=True)
    currency_id_company = fields.Many2one('res.currency', string='Moneda Compañia', required=True)
    journal_id = fields.Many2one('account.journal', string='Diario Retención IGTF', required=True)
    account_id = fields.Many2one('account.account', string='Cuenta retención IGFT', required=True)

    @api.onchange('amount')
    def compute_igtf_amount(self):
        for rec in self:
            rec.igtf_amount = rec.amount * rec.igtf_porcentage / 100
            rec.igtf_amount_bs = (rec.amount * rec.igtf_porcentage / 100) * rec.tax_today

    def _importe_en_moneda_compania(self):
        """Importe del IGTF expresado en la MONEDA DE COMPAÑIA.

        v308 - `debit`/`credit` de `account.move.line` viven en **moneda de
        compañía**, nunca en la moneda de la línea; el importe en la moneda de
        la línea va en `amount_currency` (ver `_prepare_reconciliation_amls` del
        core y el propio `_debit_usd`, que devuelve `debit` sin convertir porque
        `debit` ya está en moneda de compañía).

        El wizard intercambiaba los dos papeles: asignaba el IGTF en bolívares a
        `debit` y el IGTF en divisa a `amount_currency`. Con la compañía en USD y
        la alterna VES, una retención de 34,80 USD se contabilizaba como
        29.854,49 USD y la conciliación resultante **cerraba la factura entera
        como pagada**, dejando además una diferencia de cambio de 28.694 USD.

        `igtf_amount` está en divisa y `igtf_amount_bs` en la moneda alterna, así
        que el importe de compañía es uno de los dos según cuál de las dos sea la
        moneda de compañía. No se decide por el nombre de la moneda para no
        depender de hardcodear 'USD'/'VES'.
        """
        self.ensure_one()
        if self.currency_id_dif == self.env.company.currency_id:
            return self.igtf_amount_bs
        return self.igtf_amount

    def generar_retencion(self):
        for rec in self:
            line_ids = []
            account_to_reconcile = False
            # v308 - ver `_importe_en_moneda_compania`: `debit`/`credit` en
            # moneda de compañía, `amount_currency` en la moneda de la linea.
            en_compania = rec._importe_en_moneda_compania()
            if rec.invoice_id.move_type in ['out_invoice','out_refund']:
                line_ids.append((0, 0, {
                    'name': 'Retención IGTF %s' % rec.invoice_id.name,
                    'currency_id': rec.currency_id_dif.id,
                    'amount_currency': rec.igtf_amount_bs,
                    'debit': en_compania,
                    'debit_usd': rec.igtf_amount,
                    'credit': 0.0,
                    'account_id': rec.account_id.id,
                }))
                line_ids.append((0, 0, {
                    'name': 'Retención IGTF %s' % rec.invoice_id.name,
                    'currency_id': rec.currency_id_dif.id,
                    'amount_currency': - rec.igtf_amount_bs,
                    'debit': 0.0,
                    'credit': en_compania,
                    'credit_usd': rec.igtf_amount,
                    'account_id': rec.invoice_id.partner_id.property_account_receivable_id.id,
                    'partner_id': rec.invoice_id.partner_id.id,
                }))
                account_to_reconcile = rec.invoice_id.partner_id.property_account_receivable_id.id
            elif rec.invoice_id.move_type in ['in_invoice','in_refund']:
                line_ids.append((0, 0, {
                    'name': 'Retención IGTF %s' % rec.invoice_id.name,
                    'currency_id': rec.currency_id_dif.id,
                    'amount_currency': - rec.igtf_amount_bs,
                    'debit': 0.0,
                    'credit': en_compania,
                    'credit_usd': rec.igtf_amount,
                    'account_id': rec.account_id.id,
                }))
                line_ids.append((0, 0, {
                    'name': 'Retención IGTF %s' % rec.invoice_id.name,
                    'currency_id': rec.currency_id_dif.id,
                    'amount_currency': rec.igtf_amount_bs,
                    'debit': en_compania,
                    'debit_usd': rec.igtf_amount,
                    'credit': 0.0,
                    'account_id': rec.invoice_id.partner_id.property_account_payable_id.id,
                    'partner_id': rec.invoice_id.partner_id.id,
                }))
                account_to_reconcile = rec.invoice_id.partner_id.property_account_payable_id.id
            move_flete = {
                'journal_id': rec.journal_id.id,
                'currency_id': rec.currency_id_dif.id,
                'date': datetime.now(),
                'move_type': 'entry',
                'ref': 'Retención IGTF ' + rec.invoice_id.name,
                'tax_today': rec.tax_today,
                'line_ids': line_ids,
            }
            move_rete_igtf = self.env['account.move'].with_context(check_move_validity=False).create(move_flete)
            move_rete_igtf.action_post()
            rec.invoice_id.move_igtf_id = move_rete_igtf
            to_reconcile = rec.invoice_id.line_ids.filtered_domain(
                [('account_id', '=', account_to_reconcile), ('reconciled', '=', False)])
            ret_lines = move_rete_igtf.line_ids.filtered_domain(
                [('account_id', '=', account_to_reconcile), ('reconciled', '=', False)])

            # v308 - El `reconcile()` del core de v20 devuelve `None` (en v18
            # devolvia `{'partials', 'exchange_partials', ...}`), asi que
            # `results['partials']` era SIEMPRE inexistente y este bloque jamas
            # se ejecutaba: los parciales de la retencion se creaban con
            # `amount_usd = 0`. Los parciales se obtienen ahora por DIFERENCIA
            # de `matched_debit_ids`/`matched_credit_ids`, igual que hace
            # `account.move.line.reconcile()` en este mismo modulo.
            self.flush_recordset()
            lines = ret_lines + to_reconcile
            partials_before = lines.matched_debit_ids | lines.matched_credit_ids
            results = lines.reconcile() or {}
            lines.invalidate_recordset(['matched_debit_ids', 'matched_credit_ids'])
            partials = (lines.matched_debit_ids | lines.matched_credit_ids) - partials_before
            if not partials and isinstance(results, dict) and results.get('partials'):
                partials = results['partials']

            # Red de seguridad: si el reparto secuencial de `amount_usd` de
            # `reconcile()` no cubrio estos parciales, se fuerza con el residual
            # en divisa de la linea de retencion.
            if partials.filtered(lambda p: not p.amount_usd):
                ret_lines._compute_amount_residual_usd()
                monto_usd = abs(ret_lines.amount_residual_usd)
                partials.filtered(lambda p: not p.amount_usd).write({'amount_usd': monto_usd})
                ret_lines._compute_amount_residual_usd()