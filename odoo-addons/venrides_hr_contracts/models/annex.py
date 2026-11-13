# -*- coding: utf-8 -*-
from odoo import fields, models


class VenridesContractAnnex(models.Model):
    _name = 'venrides.contract.annex'
    _description = 'Anexo de contrato'
    _order = 'sequence, id'

    code = fields.Char(string='Código', required=True)
    name = fields.Char(string='Título', required=True)
    annex_type = fields.Selection([
        ('benefits', 'Beneficios'),
        ('rules', 'Normas y prohibiciones'),
        ('penalties', 'Penalidades'),
        ('rewards', 'Premiaciones'),
        ('rotation', 'Rotación de puestos'),
        ('salary', 'Tabla salarial'),
        ('other', 'Otro'),
    ], string='Tipo', required=True, default='rules')
    body = fields.Html(string='Contenido', required=True)
    sequence = fields.Integer(default=10)
    active = fields.Boolean(default=True)
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)

    _code_uniq = models.Constraint(
        'unique(code)', 'El código del anexo debe ser único.')
