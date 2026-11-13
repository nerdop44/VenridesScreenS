# -*- coding: utf-8 -*-
from odoo import api, fields, models
from odoo.exceptions import UserError


class VenridesGeneratePayments(models.TransientModel):
    _name = 'venrides.generate.payments'
    _description = 'Generar pagos por concepto'

    cycle_id = fields.Many2one(
        'venrides.pay.cycle', string='Ciclo de pago', required=True)
    pay_date = fields.Date(
        string='Fecha de pago', required=True, default=fields.Date.context_today)
    rate_bs_usd = fields.Float(
        string='Tasa oficial Bs/USD', digits=(16, 4), default=1.0)
    create_receipts = fields.Boolean(
        string='Crear recibos y enviar a firma', default=True)
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)

    @api.onchange('pay_date')
    def _onchange_pay_date(self):
        if self.pay_date:
            self.rate_bs_usd = self.env['venrides.payroll.payment']._get_bc_rate(
                self.pay_date)

    def action_generate(self):
        self.ensure_one()
        if not self.cycle_id or not self.pay_date:
            raise UserError('Indica el ciclo y la fecha de pago.')
        plans = self.env['venrides.pay.concept.plan'].search([
            ('state', '=', 'active'),
            ('cycle_id', '=', self.cycle_id.id),
            ('date_start', '<=', self.pay_date),
            ('date_end', '>=', self.pay_date),
        ])
        if not plans:
            raise UserError('No hay planes de pago activos para este ciclo y fecha.')
        created = self.env['venrides.payroll.payment']
        skipped = 0
        for plan in plans:
            existing = self.env['venrides.payroll.payment'].search([
                ('plan_id', '=', plan.id),
                ('payment_date', '=', self.pay_date),
                ('state', '!=', 'void'),
            ], limit=1)
            if existing:
                skipped += 1
                continue
            payment = self.env['venrides.payroll.payment'].create({
                'employee_id': plan.employee_id.id,
                'contract_id': plan.contract_id.id,
                'concept_id': plan.concept_id.id,
                'plan_id': plan.id,
                'payment_date': self.pay_date,
                'amount_usd': plan.amount_usd,
                'rate_bs_usd': self.rate_bs_usd,
                'company_id': self.company_id.id,
            })
            if self.create_receipts:
                payment.action_create_receipt()
            created |= payment
        if not created:
            raise UserError('Todos los pagos de este ciclo ya fueron generados.')
        return {
            'type': 'ir.actions.act_window',
            'name': 'Pagos generados',
            'res_model': 'venrides.payroll.payment',
            'view_mode': 'list,form',
            'domain': [('id', 'in', created.ids)],
            'target': 'current',
        }
