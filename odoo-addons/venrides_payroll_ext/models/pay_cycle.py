# -*- coding: utf-8 -*-
import calendar
from datetime import timedelta

from odoo import api, fields, models


WEEKDAYS = [
    ('0', 'Lunes'),
    ('1', 'Martes'),
    ('2', 'Miércoles'),
    ('3', 'Jueves'),
    ('4', 'Viernes'),
    ('5', 'Sábado'),
    ('6', 'Domingo'),
]

SCHEDULE_PAY = [
    ('weekly', 'Semanal'),
    ('bi-weekly', 'Bisemanal (cada 14 días)'),
    ('semi-monthly', 'Quincenal (2 veces al mes)'),
    ('monthly', 'Mensual'),
]


class VenridesPayCycle(models.Model):
    _name = 'venrides.pay.cycle'
    _description = 'Ciclo de pago'
    _order = 'sequence, id'

    name = fields.Char(string='Nombre', required=True)
    code = fields.Char(string='Código', required=True)
    schedule_pay = fields.Selection(
        SCHEDULE_PAY, string='Frecuencia', required=True, default='weekly')
    pay_day = fields.Selection(
        WEEKDAYS, string='Día de pago', default='1',
        help='Día de la semana en que se paga este ciclo.')
    period_days = fields.Integer(
        string='Días del periodo', compute='_compute_period_days', store=True)
    proration_mode = fields.Selection([
        ('days_30', 'Mensual / 30 × días'),
        ('period', 'Mensual / días del periodo'),
    ], string='Prorrateo', default='days_30', required=True,
        help='Cómo se prorratean los montos mensuales en periodos cortos.')
    sequence = fields.Integer(default=10)
    active = fields.Boolean(default=True)
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)
    contract_count = fields.Integer(compute='_compute_contract_count')

    _code_uniq = models.Constraint(
        'unique(code)', 'El código del ciclo debe ser único.')

    @api.depends('schedule_pay')
    def _compute_period_days(self):
        days = {'weekly': 7, 'bi-weekly': 14, 'semi-monthly': 15, 'monthly': 30}
        for cycle in self:
            cycle.period_days = days.get(cycle.schedule_pay, 30)

    def _compute_contract_count(self):
        for cycle in self:
            cycle.contract_count = self.env['hr.contract'].search_count(
                [('pay_cycle_id', '=', cycle.id)])

    def _get_period(self, pay_date):
        self.ensure_one()
        pay_date = fields.Date.to_date(pay_date)
        if self.schedule_pay == 'monthly':
            last_day = calendar.monthrange(pay_date.year, pay_date.month)[1]
            return pay_date.replace(day=1), pay_date.replace(day=last_day)
        if self.schedule_pay == 'semi-monthly':
            if pay_date.day <= 15:
                return pay_date.replace(day=1), pay_date.replace(day=15)
            last_day = calendar.monthrange(pay_date.year, pay_date.month)[1]
            return pay_date.replace(day=16), pay_date.replace(day=last_day)
        days = self.period_days or 7
        return pay_date - timedelta(days=days - 1), pay_date

    def _get_structure(self):
        self.ensure_one()
        refs = {
            'weekly': 'venrides_payroll.structure_semanal',
            'bi-weekly': 'venrides_payroll.structure_quincenal',
            'semi-monthly': 'venrides_payroll.structure_quincenal',
            'monthly': 'venrides_payroll.structure_mensual',
        }
        return self.env.ref(refs.get(self.schedule_pay), raise_if_not_found=False)

    def _get_contracts(self, date_from, date_to):
        self.ensure_one()
        return self.env['hr.contract'].search([
            ('pay_cycle_id', '=', self.id),
            ('state', 'in', ('open', 'pending')),
            ('date_start', '<=', date_to),
            '|', ('date_end', '=', False), ('date_end', '>=', date_from),
        ])

    def action_view_contracts(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Contratos en este ciclo',
            'res_model': 'hr.contract',
            'view_mode': 'list,form',
            'domain': [('pay_cycle_id', '=', self.id)],
        }
