# -*- coding: utf-8 -*-
from datetime import timedelta

from odoo import api, fields, models
from odoo.exceptions import UserError, ValidationError


class VenridesRotationPlan(models.Model):
    _name = 'venrides.rotation.plan'
    _description = 'Plan de rotación de puestos'
    _order = 'start_date desc, id desc'

    name = fields.Char(string='Nombre', required=True)
    code = fields.Char(string='Código', required=True)
    employee_ids = fields.Many2many(
        'hr.employee', 'venrides_rotation_employee_rel', 'plan_id', 'employee_id',
        string='Empleados')
    job_ids = fields.Many2many(
        'hr.job', 'venrides_rotation_job_rel', 'plan_id', 'job_id',
        string='Puestos a rotar', help='El orden de la lista define la secuencia.')
    start_date = fields.Date(string='Inicio', required=True,
                             default=fields.Date.context_today)
    frequency_days = fields.Integer(string='Frecuencia (días)', default=30, required=True)
    duration_days = fields.Integer(string='Duración (días)', default=30, required=True)
    periods_count = fields.Integer(string='Periodos a generar', default=12, required=True)
    line_ids = fields.One2many(
        'venrides.rotation.line', 'plan_id', string='Calendario')
    active = fields.Boolean(default=True)
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)

    _code_uniq = models.Constraint(
        'unique(code)', 'El código del plan debe ser único.')

    @api.constrains('frequency_days', 'duration_days')
    def _check_days(self):
        for plan in self:
            if plan.frequency_days < 1 or plan.duration_days < 1:
                raise ValidationError('La frecuencia y la duración deben ser mayores a cero.')
            if plan.duration_days > plan.frequency_days:
                raise ValidationError(
                    'La duración no puede ser mayor que la frecuencia: los periodos se solaparían.')

    def action_generate(self):
        for plan in self:
            if not plan.employee_ids or not plan.job_ids:
                raise UserError('Debes seleccionar al menos un empleado y un puesto.')
            plan.line_ids.unlink()
            lines = []
            for employee in plan.employee_ids:
                for index in range(plan.periods_count):
                    job = plan.job_ids[index % len(plan.job_ids)]
                    date_start = plan.start_date + timedelta(days=index * plan.frequency_days)
                    date_end = date_start + timedelta(days=plan.duration_days - 1)
                    lines.append((0, 0, {
                        'employee_id': employee.id,
                        'job_id': job.id,
                        'sequence': index,
                        'date_start': date_start,
                        'date_end': date_end,
                    }))
            plan.write({'line_ids': lines})
        return True


class VenridesRotationLine(models.Model):
    _name = 'venrides.rotation.line'
    _description = 'Turno de rotación'
    _order = 'date_start, employee_id'

    plan_id = fields.Many2one(
        'venrides.rotation.plan', string='Plan', required=True, ondelete='cascade')
    employee_id = fields.Many2one('hr.employee', string='Empleado', required=True)
    job_id = fields.Many2one('hr.job', string='Puesto', required=True)
    sequence = fields.Integer(default=10)
    date_start = fields.Date(string='Desde', required=True)
    date_end = fields.Date(string='Hasta', required=True)
    state = fields.Selection([
        ('planned', 'Programado'),
        ('current', 'En curso'),
        ('done', 'Finalizado'),
    ], string='Estado', compute='_compute_state')

    def _compute_state(self):
        today = fields.Date.context_today(self)
        for line in self:
            if line.date_end < today:
                line.state = 'done'
            elif line.date_start <= today <= line.date_end:
                line.state = 'current'
            else:
                line.state = 'planned'
