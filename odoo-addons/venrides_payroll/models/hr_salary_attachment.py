# -*- coding: utf-8 -*-
from odoo import models, fields, api
from odoo.tools import float_is_zero


class HRSalaryAttachment(models.Model):
    _name = 'hr.salary.attachment'
    _description = 'Salary Attachment'

    name = fields.Char(string='Description', required=True)
    description = fields.Char(string='Detalle')
    employee_id = fields.Many2one('hr.employee', string='Empleado')
    state = fields.Selection([
        ('open', 'Open'),
        ('closed', 'Closed'),
    ], string='State', default='open')
    date_start = fields.Date(string='Date Start')
    date_end = fields.Date(string='Date End')
    other_input_type_id = fields.Many2one('hr.payslip.input.type', string='Input Type')
    amount = fields.Float(string='Amount', default=0)

    def _get_active_amount(self):
        self.ensure_one()
        return self.amount if self.state == 'open' else 0.0
