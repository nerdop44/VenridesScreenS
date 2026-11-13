# -*- coding: utf-8 -*-
from odoo import api, fields, models
from odoo.exceptions import ValidationError


class VenridesEmployeeAccount(models.Model):
    _name = 'venrides.employee.account'
    _description = 'Cuenta de consumo del empleado'
    _order = 'employee_id'

    employee_id = fields.Many2one(
        'hr.employee', string='Empleado', required=True, ondelete='cascade')
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)
    currency_id = fields.Many2one(
        'res.currency', default=lambda self: self.env.ref('base.USD', raise_if_not_found=False))
    credit_limit = fields.Monetary(
        string='Límite de crédito', currency_field='currency_id', default=0.0)
    settlement_mode = fields.Selection([
        ('full', 'Descontar el 100 % de la deuda'),
        ('percent', 'Descontar un porcentaje'),
        ('fixed', 'Descontar un monto fijo'),
    ], string='Forma de descuento', default='full', required=True)
    settlement_percent = fields.Float(string='Porcentaje a descontar (%)', default=100.0)
    settlement_fixed = fields.Monetary(
        string='Monto fijo a descontar', currency_field='currency_id', default=0.0)
    line_ids = fields.One2many(
        'venrides.employee.account.line', 'account_id', string='Movimientos')
    balance = fields.Monetary(
        string='Saldo', currency_field='currency_id',
        compute='_compute_balance', store=True)
    active = fields.Boolean(default=True)

    _employee_uniq = models.Constraint(
        'unique(employee_id)', 'El empleado ya tiene una cuenta de consumo.')

    @api.depends('line_ids.amount', 'line_ids.state')
    def _compute_balance(self):
        for account in self:
            account.balance = sum(
                account.line_ids.filtered(lambda l: l.state == 'posted').mapped('amount'))

    def get_deduction_amount(self):
        self.ensure_one()
        balance = self.balance
        if balance <= 0:
            return 0.0
        if self.settlement_mode == 'percent':
            amount = balance * self.settlement_percent / 100.0
        elif self.settlement_mode == 'fixed':
            amount = self.settlement_fixed
        else:
            amount = balance
        return max(0.0, min(amount, balance))

    def apply_to_payslip(self, payslip):
        self.ensure_one()
        existing = self.line_ids.filtered(
            lambda l: l.payslip_id == payslip and l.line_type == 'payroll_deduction')
        if existing:
            return 0.0
        amount = self.get_deduction_amount()
        if amount <= 0:
            return 0.0
        self.env['venrides.employee.account.line'].create({
            'account_id': self.id,
            'date': payslip.date_to,
            'name': 'Descuento de nómina %s' % (payslip.number or ''),
            'amount': -amount,
            'line_type': 'payroll_deduction',
            'payslip_id': payslip.id,
            'state': 'posted',
        })
        return amount


class VenridesEmployeeAccountLine(models.Model):
    _name = 'venrides.employee.account.line'
    _description = 'Movimiento de cuenta de empleado'
    _order = 'date desc, id desc'

    account_id = fields.Many2one(
        'venrides.employee.account', string='Cuenta', required=True, ondelete='cascade')
    date = fields.Date(string='Fecha', default=fields.Date.context_today, required=True)
    name = fields.Char(string='Descripción', required=True)
    amount = fields.Monetary(
        string='Monto', currency_field='currency_id',
        help='Positivo = consumo (deuda). Negativo = pago o descuento.')
    currency_id = fields.Many2one(related='account_id.currency_id', store=True)
    line_type = fields.Selection([
        ('consumption', 'Consumo'),
        ('payment', 'Pago'),
        ('payroll_deduction', 'Descuento de nómina'),
        ('adjustment', 'Ajuste'),
    ], string='Tipo', default='consumption', required=True)
    payslip_id = fields.Many2one('hr.payslip', string='Recibo de nómina')
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('posted', 'Contabilizado'),
        ('cancelled', 'Anulado'),
    ], string='Estado', default='posted', required=True)
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)

    @api.constrains('amount')
    def _check_amount(self):
        for line in self:
            if line.amount == 0:
                raise ValidationError('El monto del movimiento no puede ser cero.')
