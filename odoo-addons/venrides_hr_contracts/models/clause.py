# -*- coding: utf-8 -*-
from odoo import fields, models


class VenridesContractClause(models.Model):
    _name = 'venrides.contract.clause'
    _description = 'Cláusula de contrato'
    _order = 'sequence, id'

    code = fields.Char(string='Código', required=True)
    name = fields.Char(string='Título', required=True)
    clause_type = fields.Selection([
        ('general', 'General (todo el personal)'),
        ('specific', 'Específica (por puesto)'),
    ], string='Tipo', required=True, default='general')
    body = fields.Html(string='Texto de la cláusula', required=True)
    job_ids = fields.Many2many(
        'hr.job', 'venrides_clause_job_rel', 'clause_id', 'job_id',
        string='Puestos aplicables')
    mandatory = fields.Boolean(string='Obligatoria', default=True)
    sequence = fields.Integer(default=10)
    active = fields.Boolean(default=True)
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)

    _code_uniq = models.Constraint(
        'unique(code)', 'El código de la cláusula debe ser único.')
