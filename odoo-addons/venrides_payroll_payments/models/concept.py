# -*- coding: utf-8 -*-
from odoo import fields, models


class VenridesPayConcept(models.Model):
    _name = 'venrides.pay.concept'
    _description = 'Concepto de pago'
    _order = 'code'

    code = fields.Char(string='Código', required=True)
    name = fields.Char(string='Nombre', required=True)
    concept_type = fields.Selection([
        ('earning', 'Asignación'),
        ('deduction', 'Deducción'),
    ], string='Tipo', default='earning', required=True)
    rule_code = fields.Char(string='Código de regla de nómina')
    default_amount_usd = fields.Monetary(
        string='Monto por defecto (USD)', currency_field='currency_id', default=0.0)
    currency_id = fields.Many2one(
        'res.currency', default=lambda self: self.env.ref('base.USD', raise_if_not_found=False))
    active = fields.Boolean(default=True)
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)

    _code_uniq = models.Constraint(
        'unique(code)', 'El código del concepto debe ser único.')
