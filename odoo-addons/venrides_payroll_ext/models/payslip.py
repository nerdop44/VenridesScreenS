# -*- coding: utf-8 -*-
from odoo import api, fields, models


class HrPayslip(models.Model):
    _inherit = 'hr.payslip'

    pay_cycle_id = fields.Many2one('venrides.pay.cycle', string='Ciclo de pago')
    pay_day = fields.Selection(
        [('0', 'Lunes'), ('1', 'Martes'), ('2', 'Miércoles'), ('3', 'Jueves'),
         ('4', 'Viernes'), ('5', 'Sábado'), ('6', 'Domingo')],
        string='Día de pago')
    performance_evaluation_id = fields.Many2one(
        'venrides.performance.evaluation', string='Evaluación de desempeño')
    performance_bonus_usd = fields.Monetary(
        string='Bono de desempeño (USD)', currency_field='currency_id_dif', default=0.0)
    employee_deduction_usd = fields.Monetary(
        string='Descuento de consumo (USD)', currency_field='currency_id_dif', default=0.0)
    voucher_usd = fields.Monetary(
        string='Vales de comida (USD)', currency_field='currency_id_dif', default=0.0)
    receipt_mode = fields.Selection(
        related='company_id.venrides_receipt_mode', string='Modo de recibo')

    def _get_performance_evaluation(self):
        self.ensure_one()
        return self.env['venrides.performance.evaluation'].search([
            ('employee_id', '=', self.employee_id.id),
            ('state', '=', 'confirmed'),
            ('period_id.date_from', '<=', self.date_to),
            ('period_id.date_to', '>=', self.date_to),
        ], order='period_id desc', limit=1)

    def action_load_performance_bonus(self):
        for payslip in self:
            evaluation = payslip._get_performance_evaluation()
            if not evaluation:
                payslip.performance_bonus_usd = 0.0
                continue
            payslip.write({
                'performance_evaluation_id': evaluation.id,
                'performance_bonus_usd': evaluation.bonus_usd,
            })
        return True

    def action_apply_employee_account(self):
        for payslip in self:
            account = self.env['venrides.employee.account'].search(
                [('employee_id', '=', payslip.employee_id.id)], limit=1)
            if not account:
                continue
            amount = account.apply_to_payslip(payslip)
            if amount:
                payslip.employee_deduction_usd = amount
        return True

    def action_open_concept_receipt(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Recibo por concepto',
            'res_model': 'venrides.payslip.concept.receipt',
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_payslip_id': self.id},
        }
