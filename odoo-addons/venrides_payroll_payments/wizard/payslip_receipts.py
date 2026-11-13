# -*- coding: utf-8 -*-
from odoo import api, fields, models
from odoo.exceptions import UserError


class VenridesPayslipReceipts(models.TransientModel):
    _name = 'venrides.payslip.receipts'
    _description = 'Generar recibos por concepto desde la nómina'

    payslip_id = fields.Many2one('hr.payslip', string='Recibo de nómina', required=True)
    line_ids = fields.Many2many(
        'hr.payslip.line', 'venrides_payslip_receipt_line_rel',
        'wizard_id', 'line_id', string='Conceptos a pagar',
        domain="[('slip_id', '=', payslip_id)]")
    payment_date = fields.Date(string='Fecha de pago', required=True)
    rate_bs_usd = fields.Float(
        string='Tasa oficial Bs/USD', digits=(16, 4), default=1.0)
    create_receipts = fields.Boolean(
        string='Crear recibos y enviar a firma', default=True)

    @api.onchange('payslip_id')
    def _onchange_payslip(self):
        if self.payslip_id:
            self.payment_date = self.payslip_id.date_to
            self.rate_bs_usd = self.payslip_id.tasa_cambio or 1.0
            self.line_ids = self.payslip_id.line_ids.filtered(
                lambda l: l.appears_on_payslip and l.total > 0
                and l.category_id.code in ('BASIC', 'BONO', 'ASIGNA', 'SUBS'))

    def action_generate(self):
        self.ensure_one()
        if not self.line_ids:
            raise UserError('Selecciona al menos un concepto.')
        payslip = self.payslip_id
        created = self.env['venrides.payroll.payment']
        for line in self.line_ids:
            amount_usd = line.total / payslip.tasa_cambio if payslip.tasa_cambio else line.total
            concept = self.env['venrides.pay.concept'].search(
                [('code', '=', line.code)], limit=1)
            if not concept:
                concept = self.env['venrides.pay.concept'].create({
                    'code': line.code,
                    'name': line.name,
                    'rule_code': line.code,
                    'default_amount_usd': amount_usd,
                })
            payment = self.env['venrides.payroll.payment'].create({
                'employee_id': payslip.employee_id.id,
                'contract_id': payslip.contract_id.id,
                'concept_id': concept.id,
                'payslip_id': payslip.id,
                'payment_date': self.payment_date,
                'amount_usd': round(amount_usd, 2),
                'rate_bs_usd': self.rate_bs_usd,
            })
            if self.create_receipts:
                payment.action_create_receipt()
            created |= payment
        return {
            'type': 'ir.actions.act_window',
            'name': 'Recibos por concepto',
            'res_model': 'venrides.payroll.payment',
            'view_mode': 'list,form',
            'domain': [('id', 'in', created.ids)],
            'target': 'current',
        }
