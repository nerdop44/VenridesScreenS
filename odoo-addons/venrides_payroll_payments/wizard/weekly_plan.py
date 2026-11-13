# -*- coding: utf-8 -*-
from datetime import timedelta

from odoo import api, fields, models
from odoo.exceptions import UserError


class VenridesWeeklyPlanLine(models.TransientModel):
    _name = 'venrides.weekly.plan.line'
    _description = 'Línea del plan semanal'
    _order = 'week, id'

    wizard_id = fields.Many2one(
        'venrides.weekly.plan', string='Asistente', ondelete='cascade')
    week = fields.Integer(string='Semana', default=1, required=True)
    concept_id = fields.Many2one('venrides.pay.concept', string='Concepto', required=True)
    amount_usd = fields.Monetary(
        string='Monto (USD)', currency_field='currency_id', required=True)
    currency_id = fields.Many2one(
        'res.currency', default=lambda self: self.env.ref('base.USD', raise_if_not_found=False))


class VenridesWeeklyPlan(models.TransientModel):
    _name = 'venrides.weekly.plan'
    _description = 'Generar plan semanal por concepto'

    contract_id = fields.Many2one('hr.contract', string='Contrato', required=True)
    employee_id = fields.Many2one(
        'hr.employee', string='Empleado', related='contract_id.employee_id')
    start_date = fields.Date(
        string='Primer día de pago', required=True,
        default=fields.Date.context_today)
    cycle_id = fields.Many2one(
        'venrides.pay.cycle', string='Ciclo de pago', required=True)
    line_ids = fields.One2many(
        'venrides.weekly.plan.line', 'wizard_id', string='Distribución semanal')

    def _get_concept(self, code, name):
        concept = self.env['venrides.pay.concept'].search([('code', '=', code)], limit=1)
        if not concept:
            concept = self.env['venrides.pay.concept'].create({
                'code': code,
                'name': name,
                'concept_type': 'earning',
            })
        return concept

    def _build_lines(self, contract):
        if not contract:
            return [(5, 0, 0)]
        return [
            (0, 0, {'week': 1, 'concept_id': self._get_concept('BONOGUE', 'Bono de guerra').id,
                    'amount_usd': contract.bono_guerra_usd}),
            (0, 0, {'week': 2, 'concept_id': self._get_concept('BONODES', 'Bono de desempeño').id,
                    'amount_usd': contract.bono_desempeno_max_usd}),
            (0, 0, {'week': 3, 'concept_id': self._get_concept('BONOTRA', 'Bono de transporte').id,
                    'amount_usd': contract.bono_transporte_usd}),
            (0, 0, {'week': 4, 'concept_id': self._get_concept('SMENS', 'Salario base').id,
                    'amount_usd': contract.wage_usd}),
            (0, 0, {'week': 4, 'concept_id': self._get_concept('CESTAT', 'Cestatickets').id,
                    'amount_usd': contract.cestaticket_usd}),
        ]

    @api.model
    def default_get(self, fields_list):
        result = super().default_get(fields_list)
        contract = self.env['hr.contract'].browse(
            self.env.context.get('default_contract_id') or self.env.context.get('active_id'))
        if contract:
            result.setdefault('contract_id', contract.id)
            result.setdefault('line_ids', self._build_lines(contract))
            cycle = contract.pay_cycle_id
            if cycle:
                result.setdefault('cycle_id', cycle.id)
        return result

    @api.onchange('contract_id')
    def _onchange_contract(self):
        if self.contract_id:
            self.line_ids = self._build_lines(self.contract_id)
            if self.contract_id.pay_cycle_id:
                self.cycle_id = self.contract_id.pay_cycle_id

    def action_create(self):
        self.ensure_one()
        if not self.line_ids:
            raise UserError('El plan no tiene líneas.')
        Plan = self.env['venrides.pay.concept.plan']
        for line in self.line_ids:
            date_start = self.start_date + timedelta(days=(line.week - 1) * 7)
            date_end = date_start + timedelta(days=6)
            Plan.create({
                'contract_id': self.contract_id.id,
                'concept_id': line.concept_id.id,
                'amount_usd': line.amount_usd,
                'cycle_id': self.cycle_id.id,
                'date_start': date_start,
                'date_end': date_end,
                'state': 'active',
            })
        return {
            'type': 'ir.actions.act_window',
            'name': 'Planes de pago',
            'res_model': 'venrides.pay.concept.plan',
            'view_mode': 'list,form',
            'domain': [('contract_id', '=', self.contract_id.id)],
            'target': 'current',
        }
