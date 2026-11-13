
from odoo import models, fields,api

class HRPayslipInputType(models.Model):
    _name = 'hr.payslip.input.type'
    _description = 'Payslip Input Type'

    name = fields.Char(string='Name', required=True)
    code = fields.Char(string='Code')

    monstar_automatico = fields.Boolean(string="Mostrar automatico", default=True)
    available_in_attachments = fields.Boolean(string="Available in Attachments", default=False)
    struct_ids = fields.Many2many('hr.payroll.structure', string='Structures')
