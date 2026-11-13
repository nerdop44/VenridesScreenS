# -*- coding: utf-8 -*-
from odoo import api, fields, models
from odoo.exceptions import UserError


class VenridesGeneratePayroll(models.TransientModel):
    _name = 'venrides.generate.payroll'
    _description = 'Generar nómina por ciclo'

    cycle_id = fields.Many2one(
        'venrides.pay.cycle', string='Ciclo de pago', required=True)
    pay_date = fields.Date(
        string='Fecha de pago', required=True,
        default=fields.Date.context_today)
    date_from = fields.Date(string='Desde', compute='_compute_period', store=False)
    date_to = fields.Date(string='Hasta', compute='_compute_period', store=False)
    structure_id = fields.Many2one(
        'hr.payroll.structure', string='Estructura de nómina')
    tasa_cambio = fields.Float(string='Tasa de cambio (Bs/USD)', default=1.0, digits=(16, 4))
    create_run = fields.Boolean(string='Crear lote de nómina', default=True)
    run_name = fields.Char(string='Nombre del lote')
    include_performance = fields.Boolean(
        string='Incluir bono de desempeño confirmado', default=True)
    include_account = fields.Boolean(
        string='Incluir descuento de consumo', default=True)
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)

    @api.depends('cycle_id', 'pay_date')
    def _compute_period(self):
        for wizard in self:
            if wizard.cycle_id and wizard.pay_date:
                date_from, date_to = wizard.cycle_id._get_period(wizard.pay_date)
                wizard.date_from = date_from
                wizard.date_to = date_to
            else:
                wizard.date_from = False
                wizard.date_to = False

    @api.onchange('cycle_id')
    def _onchange_cycle(self):
        if self.cycle_id:
            self.structure_id = self.cycle_id._get_structure()
            if not self.run_name:
                self.run_name = 'Nómina %s — %s' % (
                    self.cycle_id.name, self.pay_date or '')

    def action_generate(self):
        self.ensure_one()
        if not self.cycle_id:
            raise UserError('Selecciona un ciclo de pago.')
        date_from, date_to = self.cycle_id._get_period(self.pay_date)
        structure = self.structure_id or self.cycle_id._get_structure()
        if not structure:
            raise UserError('No hay una estructura de nómina configurada para este ciclo.')

        contracts = self.cycle_id._get_contracts(date_from, date_to)
        if not contracts:
            raise UserError('No hay contratos vigentes en este ciclo para el periodo.')

        run = False
        if self.create_run:
            run = self.env['hr.payslip.run'].create({
                'name': self.run_name or 'Nómina %s' % self.cycle_id.name,
                'date_start': date_from,
                'date_end': date_to,
                'company_id': self.company_id.id,
                'tasa_cambio': self.tasa_cambio,
            })

        created = self.env['hr.payslip']
        skipped = self.env['hr.contract']
        for contract in contracts:
            existing = self.env['hr.payslip'].search([
                ('employee_id', '=', contract.employee_id.id),
                ('date_from', '=', date_from),
                ('date_to', '=', date_to),
                ('state', '!=', 'cancel'),
            ], limit=1)
            if existing:
                skipped |= contract
                continue
            payslip = self.env['hr.payslip'].create({
                'employee_id': contract.employee_id.id,
                'contract_id': contract.id,
                'struct_id': structure.id,
                'date_from': date_from,
                'date_to': date_to,
                'tasa_cambio': self.tasa_cambio,
                'pay_cycle_id': self.cycle_id.id,
                'pay_day': contract.pay_day or self.cycle_id.pay_day,
                'payslip_run_id': run.id if run else False,
                'company_id': self.company_id.id,
            })
            if self.include_performance:
                payslip.action_load_performance_bonus()
            if self.include_account:
                payslip.action_apply_employee_account()
            payslip.compute_sheet()
            created |= payslip

        if not created:
            raise UserError(
                'Todos los empleados del ciclo ya tienen nómina para este periodo.')

        message = '%s recibo(s) generado(s).' % len(created)
        if skipped:
            message += ' %s contrato(s) omitido(s) por nómina existente.' % len(skipped)

        if run:
            return {
                'type': 'ir.actions.act_window',
                'name': 'Lote de nómina',
                'res_model': 'hr.payslip.run',
                'res_id': run.id,
                'view_mode': 'form',
                'target': 'current',
                'context': {'default_message': message},
            }
        return {
            'type': 'ir.actions.act_window',
            'name': 'Recibos generados',
            'res_model': 'hr.payslip',
            'view_mode': 'list,form',
            'domain': [('id', 'in', created.ids)],
            'target': 'current',
        }
