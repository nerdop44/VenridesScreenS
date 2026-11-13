# -*- coding: utf-8 -*-
from odoo import api, fields, models


class VenridesSalaryTable(models.Model):
    _name = 'venrides.salary.table'
    _description = 'Tabla salarial'
    _order = 'date_from desc, id desc'

    name = fields.Char(string='Nombre', required=True)
    code = fields.Char(string='Código', required=True)
    date_from = fields.Date(string='Vigente desde', required=True,
                            default=fields.Date.context_today)
    date_to = fields.Date(string='Vigente hasta')
    currency_id = fields.Many2one(
        'res.currency', string='Moneda',
        default=lambda self: self.env.ref('base.USD', raise_if_not_found=False))
    line_ids = fields.One2many(
        'venrides.salary.table.line', 'table_id', string='Líneas')
    active = fields.Boolean(default=True)
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)

    _code_uniq = models.Constraint(
        'unique(code)', 'El código de la tabla salarial debe ser único.')

    def name_get(self):
        return [(table.id, '%s (%s)' % (table.name, table.code)) for table in self]


class VenridesSalaryTableLine(models.Model):
    _name = 'venrides.salary.table.line'
    _description = 'Línea de tabla salarial'
    _order = 'table_id, job_id'

    table_id = fields.Many2one(
        'venrides.salary.table', string='Tabla', required=True, ondelete='cascade')
    job_id = fields.Many2one('hr.job', string='Puesto', required=True)
    currency_id = fields.Many2one(
        'res.currency', related='table_id.currency_id', store=True)
    base_usd = fields.Monetary(
        string='Salario base', currency_field='currency_id', default=0.0)
    bono_guerra_usd = fields.Monetary(
        string='Bono de guerra', currency_field='currency_id', default=0.0)
    bono_transporte_usd = fields.Monetary(
        string='Bono transporte/asistencia', currency_field='currency_id', default=0.0)
    bono_desempeno_max_usd = fields.Monetary(
        string='Bono desempeño (máximo)', currency_field='currency_id', default=0.0)
    cestaticket_usd = fields.Monetary(
        string='Cestatickets', currency_field='currency_id', default=0.0)
    total_usd = fields.Monetary(
        string='Total referencial', currency_field='currency_id',
        compute='_compute_total', store=True)
    notes = fields.Char(string='Notas')

    _table_job_uniq = models.Constraint(
        'unique(table_id, job_id)', 'El puesto ya está en esta tabla salarial.')

    @api.depends('base_usd', 'bono_guerra_usd', 'bono_transporte_usd',
                 'bono_desempeno_max_usd', 'cestaticket_usd')
    def _compute_total(self):
        for line in self:
            line.total_usd = (
                line.base_usd + line.bono_guerra_usd + line.bono_transporte_usd
                + line.bono_desempeno_max_usd + line.cestaticket_usd)
