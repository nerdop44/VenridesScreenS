# -*- coding: utf-8 -*-
from odoo import models, fields, api


class HRPayrollRuleParameter(models.Model):
    _name = 'hr.rule.parameter'
    _description = 'Payroll Rule Parameter'

    code = fields.Char(string='Code')
    reference_date = fields.Date(string='Reference Date')
    value = fields.Float(string='Value', default=0)
    factor = fields.Float(string='Factor', default=1)

    @api.model
    def _get_parameter_from_code(self, code, reference_date=None):
        domain = [('code', '=', code)]
        if reference_date:
            domain += [('reference_date', '<=', reference_date)]
        return self.search(domain, limit=1)
