# -*- coding: utf-8 -*-
from odoo import models, fields, api


class HRPayslipInput(models.Model):
    _name = 'hr.payslip.input'
    _description = 'Payslip Input'

    payslip_id = fields.Many2one('hr.payslip', string='Payslip', required=True, ondelete='cascade')
    input_type_id = fields.Many2one('hr.payslip.input.type', string='Input Type', required=True, ondelete='cascade')
    amount = fields.Float(string='Amount', default=0)
    code = fields.Char(string='Code')
    name = fields.Char(string='Name')
