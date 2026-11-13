# -*- coding: utf-8 -*-
from odoo import api, fields, models


class HrContract(models.Model):
    _inherit = 'hr.contract'

    schedule_pay = fields.Selection(
        selection_add=[('semi-monthly', 'Quincenal')],
        ondelete={'semi-monthly': 'set default'})
    pay_cycle_id = fields.Many2one(
        'venrides.pay.cycle', string='Ciclo de pago', index=True)
    pay_day = fields.Selection(
        [('0', 'Lunes'), ('1', 'Martes'), ('2', 'Miércoles'), ('3', 'Jueves'),
         ('4', 'Viernes'), ('5', 'Sábado'), ('6', 'Domingo')],
        string='Día de pago')
    pay_frequency = fields.Selection(
        related='pay_cycle_id.schedule_pay', string='Frecuencia de pago', store=True)
    pay_day_conflict = fields.Boolean(
        string='Coincide con otro empleado', compute='_compute_pay_day_conflict')
    employee_account_id = fields.Many2one(
        'venrides.employee.account', string='Cuenta de consumo',
        compute='_compute_employee_account')

    @api.depends('pay_day', 'company_id', 'state')
    def _compute_pay_day_conflict(self):
        for contract in self:
            if not contract.pay_day:
                contract.pay_day_conflict = False
                continue
            contract.pay_day_conflict = bool(self.search_count([
                ('id', '!=', contract.id or 0),
                ('company_id', '=', contract.company_id.id),
                ('pay_day', '=', contract.pay_day),
                ('state', 'in', ('open', 'pending')),
            ]))

    @api.depends('employee_id')
    def _compute_employee_account(self):
        for contract in self:
            contract.employee_account_id = self.env['venrides.employee.account'].search(
                [('employee_id', '=', contract.employee_id.id)], limit=1)

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if vals.get('pay_cycle_id'):
                cycle = self.env['venrides.pay.cycle'].browse(vals['pay_cycle_id'])
                if not vals.get('schedule_pay'):
                    vals['schedule_pay'] = cycle.schedule_pay
                if not vals.get('pay_day'):
                    vals['pay_day'] = cycle.pay_day
        return super().create(vals_list)

    @api.onchange('pay_cycle_id')
    def _onchange_pay_cycle_id(self):
        if self.pay_cycle_id:
            self.schedule_pay = self.pay_cycle_id.schedule_pay
            self.pay_day = self.pay_cycle_id.pay_day
            conflict = self.search_count([
                ('id', '!=', self._origin.id or 0),
                ('company_id', '=', self.company_id.id),
                ('pay_day', '=', self.pay_day),
                ('state', 'in', ('open', 'pending')),
            ])
            if conflict:
                return {'warning': {
                    'title': 'Día de pago repetido',
                    'message': 'Ya hay %s empleado(s) con el día de pago %s. '
                               'Verifica que sea intencional.' % (
                                   conflict, dict(self._fields['pay_day'].selection).get(self.pay_day)),
                }}
        return None
