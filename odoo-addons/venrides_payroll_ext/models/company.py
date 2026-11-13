# -*- coding: utf-8 -*-
from odoo import fields, models


class ResCompany(models.Model):
    _inherit = 'res.company'

    venrides_receipt_mode = fields.Selection([
        ('unified', 'Recibo unificado'),
        ('per_concept', 'Recibos por concepto'),
    ], string='Modo de recibo de nómina', default='unified')
    venrides_deduction_base_mode = fields.Selection([
        ('base', 'Solo salario base'),
        ('total', 'Salario base + bonos'),
    ], string='Base de deducciones de ley', default='base',
        help='Base para FAOV e ISLR. IVSS y RPE ya se calculan sobre el salario base.')
