# -*- coding: utf-8 -*-
from odoo import fields, models


class VenridesEmployeeDocument(models.Model):
    _inherit = 'venrides.employee.document'

    payment_id = fields.Many2one(
        'venrides.payroll.payment', string='Pago por concepto', index=True)
