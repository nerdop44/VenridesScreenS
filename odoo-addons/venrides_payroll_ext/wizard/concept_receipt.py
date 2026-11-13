# -*- coding: utf-8 -*-
from odoo import api, fields, models


class VenridesPayslipConceptReceipt(models.TransientModel):
    _name = 'venrides.payslip.concept.receipt'
    _description = 'Recibo de nómina por concepto'

    payslip_id = fields.Many2one(
        'hr.payslip', string='Recibo de nómina', required=True)
    line_ids = fields.Many2many(
        'hr.payslip.line', 'venrides_concept_receipt_line_rel',
        'wizard_id', 'line_id', string='Conceptos',
        domain="[('slip_id', '=', payslip_id)]")

    @api.onchange('payslip_id')
    def _onchange_payslip(self):
        if self.payslip_id:
            self.line_ids = self.payslip_id.line_ids.filtered('appears_on_payslip')

    def action_print(self):
        self.ensure_one()
        report = self.env.ref(
            'venrides_payroll_ext.action_report_payslip_concept')
        return report.report_action(
            self.payslip_id,
            data={'line_ids': self.line_ids.ids})
