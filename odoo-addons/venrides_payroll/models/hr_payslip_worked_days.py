
from odoo import models, fields,api

class HRPayslipWorkedDays(models.Model):
    _name = 'hr.payslip.worked_days'
    _description = 'Payslip Worked Days'

    payslip_id = fields.Many2one('hr.payslip', string='Payslip', required=True, ondelete='cascade')
    sequence = fields.Integer(string='Secuencia', default=10)
    work_entry_type_id = fields.Many2one('hr.work.entry.type', string='Tipo de Entrada')
    amount = fields.Float(string='Amount', default=0)
    number_of_days = fields.Float(string='Number of Days', default=0)
    number_of_hours = fields.Float(string='Number of Hours', default=0)
    code = fields.Char(string='Code', related='work_entry_type_id.code', store=True, readonly=True)
    is_paid = fields.Boolean(string='Is Paid')
    is_credit_time = fields.Boolean(string='Is Credit Time')
    is_regular = fields.Boolean(string='Is Regular')

    @api.depends('amount','payslip_id.tasa_cambio')
    def _amount_usd(self):
        #tax_today_id = self.env['res.currency'].search([('name', '=', 'USD')])
        for record in self:
            if record.payslip_id:
                if record.payslip_id.tasa_cambio>0:
                    record.amount_usd = record.amount / record.payslip_id.tasa_cambio
                else:
                    record.amount_usd = record.amount
            else:
                record.amount_usd = record.amount


    amount_usd = fields.Float(string="Importe (USD)", compute="_amount_usd")
