# -*- coding: utf-8 -*-
from odoo import api, fields, models
from odoo.exceptions import ValidationError


class VenridesPayConceptPlan(models.Model):
    _name = 'venrides.pay.concept.plan'
    _description = 'Plan de pago por concepto'
    _order = 'date_start, sequence, id'

    name = fields.Char(string='Plan', compute='_compute_name', store=True)
    contract_id = fields.Many2one(
        'hr.contract', string='Contrato', required=True, ondelete='cascade')
    employee_id = fields.Many2one(
        'hr.employee', string='Empleado', related='contract_id.employee_id',
        store=True, readonly=True)
    concept_id = fields.Many2one(
        'venrides.pay.concept', string='Concepto', required=True)
    amount_usd = fields.Monetary(
        string='Monto (USD)', currency_field='currency_id', required=True)
    currency_id = fields.Many2one(
        'res.currency', default=lambda self: self.env.ref('base.USD', raise_if_not_found=False))
    cycle_id = fields.Many2one(
        'venrides.pay.cycle', string='Ciclo de pago', required=True,
        help='Ciclo en el que se paga este concepto (martes, jueves, sábado, quincenal...).')
    date_start = fields.Date(string='Desde', required=True)
    date_end = fields.Date(string='Hasta', required=True)
    sequence = fields.Integer(default=10)
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('active', 'Activo'),
        ('done', 'Cumplido'),
        ('cancelled', 'Cancelado'),
    ], string='Estado', default='draft', required=True)
    notes = fields.Text(string='Notas')
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)

    @api.depends('concept_id', 'amount_usd', 'cycle_id')
    def _compute_name(self):
        for plan in self:
            plan.name = '%s — %.2f USD — %s' % (
                plan.concept_id.name or '',
                plan.amount_usd or 0.0,
                plan.cycle_id.name or '')

    @api.constrains('amount_usd', 'date_start', 'date_end')
    def _check_plan(self):
        for plan in self:
            if plan.amount_usd <= 0:
                raise ValidationError('El monto del plan debe ser mayor a cero.')
            if plan.date_end < plan.date_start:
                raise ValidationError('La fecha final no puede ser anterior al inicio.')

    def action_activate(self):
        self.write({'state': 'active'})

    def action_done(self):
        self.write({'state': 'done'})
