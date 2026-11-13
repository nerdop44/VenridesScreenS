# -*- coding: utf-8 -*-
from odoo import models, fields,api

class HRPayslipStructureType(models.Model):
    _inherit = 'hr.payroll.structure.type'
    _description = 'Salary Structure Type'

    code = fields.Char(string='Code')
    name = fields.Char(string='Name')
    default_schedule_pay = fields.Selection([
        ('weekly', 'Weekly'),
        ('bi-weekly', 'Bi-Weekly'),
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('semi-annually', 'Semi-Annually'),
        ('annually', 'Annually'),
    ], string='Default Schedule Pay', default='monthly')
    default_struct_id = fields.Many2one('hr.payroll.structure', string='Default Structure', ondelete='cascade')


class HRPayslipStructure(models.Model):
    _name = 'hr.payroll.structure'
    _description = 'Payroll Structure'

    name = fields.Char(string='Name', required=True)
    country_id = fields.Many2one('res.country', string='Country')
    type_id = fields.Many2one('hr.payroll.structure.type', string='Structure Type', ondelete='cascade')
    use_worked_day_lines = fields.Boolean(string='Use Worked Day Lines', default=False)
    ytd_computation = fields.Boolean(string='YTD Computation', default=False)
    rule_ids = fields.One2many(
        'hr.salary.rule', 'struct_id',
        string='Salary Rules', default=lambda self: self._get_default_rule_ids())

    procesar_prestaciones = fields.Boolean(string='Procesar Prestaciones', default=False)
    report_id = fields.Many2one('ir.actions.report', string='Reporte de Recibo')

    @api.model
    def _get_default_rule_ids(self):
        return [(5, 0, 0)]

    def wizard_copy(self):
        return {
            'view_type': 'form',
            'view_mode': 'form',
            'res_model': 'hr.payslip.structure.copy',
            'type': 'ir.actions.act_window',
            'target': 'new',
            'res_id': False,
        }
