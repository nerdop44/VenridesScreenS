# -*- coding: utf-8 -*-
from odoo import api, fields, models
from odoo.exceptions import UserError, ValidationError


class VenridesPerformancePeriod(models.Model):
    _name = 'venrides.performance.period'
    _description = 'Periodo de evaluación de desempeño'
    _order = 'date_from desc, id desc'

    name = fields.Char(string='Nombre', required=True)
    date_from = fields.Date(string='Desde', required=True)
    date_to = fields.Date(string='Hasta', required=True)
    global_weight = fields.Float(string='Peso meta global (%)', default=40.0)
    job_weight = fields.Float(string='Peso meta del puesto (%)', default=40.0)
    individual_weight = fields.Float(string='Peso meta individual (%)', default=20.0)
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('open', 'Abierto'),
        ('closed', 'Cerrado'),
    ], string='Estado', default='draft', required=True)
    goal_ids = fields.One2many(
        'venrides.performance.goal', 'period_id', string='Metas')
    evaluation_ids = fields.One2many(
        'venrides.performance.evaluation', 'period_id', string='Evaluaciones')
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)

    @api.constrains('global_weight', 'job_weight', 'individual_weight')
    def _check_weights(self):
        for period in self:
            total = period.global_weight + period.job_weight + period.individual_weight
            if abs(total - 100.0) > 0.01:
                raise ValidationError('Los pesos de las metas deben sumar 100 %.')

    @api.constrains('date_from', 'date_to')
    def _check_dates(self):
        for period in self:
            if period.date_to < period.date_from:
                raise ValidationError('La fecha final no puede ser anterior al inicio.')

    def action_open(self):
        self.write({'state': 'open'})

    def action_close(self):
        self.write({'state': 'closed'})


class VenridesPerformanceGoal(models.Model):
    _name = 'venrides.performance.goal'
    _description = 'Meta de desempeño'
    _order = 'period_id, scope, id'

    period_id = fields.Many2one(
        'venrides.performance.period', string='Periodo', required=True, ondelete='cascade')
    name = fields.Char(string='Meta', required=True)
    scope = fields.Selection([
        ('global', 'Global (toda la empresa)'),
        ('job', 'Del puesto'),
        ('individual', 'Individual'),
    ], string='Ámbito', required=True, default='global')
    job_id = fields.Many2one('hr.job', string='Puesto',
                             help='Aplica cuando el ámbito es "Del puesto".')
    employee_id = fields.Many2one('hr.employee', string='Empleado',
                                  help='Aplica cuando el ámbito es "Individual".')
    weight = fields.Float(string='Peso', default=100.0)
    target = fields.Float(string='Meta', default=100.0)
    achieved = fields.Float(string='Resultado', default=0.0)
    score = fields.Float(string='Cumplimiento (%)', compute='_compute_score', store=True)
    active = fields.Boolean(default=True)

    @api.depends('target', 'achieved')
    def _compute_score(self):
        for goal in self:
            goal.score = min(goal.achieved / goal.target, 1.0) * 100.0 if goal.target else 0.0

    @api.constrains('scope', 'job_id', 'employee_id')
    def _check_scope(self):
        for goal in self:
            if goal.scope == 'job' and not goal.job_id:
                raise ValidationError('Una meta del puesto requiere un puesto.')
            if goal.scope == 'individual' and not goal.employee_id:
                raise ValidationError('Una meta individual requiere un empleado.')


class VenridesPerformanceEvaluation(models.Model):
    _name = 'venrides.performance.evaluation'
    _description = 'Evaluación de desempeño'
    _order = 'period_id desc, employee_id'

    name = fields.Char(string='Referencia', compute='_compute_name', store=True)
    period_id = fields.Many2one(
        'venrides.performance.period', string='Periodo', required=True)
    employee_id = fields.Many2one('hr.employee', string='Empleado', required=True)
    contract_id = fields.Many2one('hr.contract', string='Contrato')
    job_id = fields.Many2one(
        'hr.job', string='Puesto evaluado',
        help='Puesto efectivo según la rotación o el contrato.')
    line_ids = fields.One2many(
        'venrides.performance.evaluation.line', 'evaluation_id', string='Detalle')
    result_pct = fields.Float(string='Cumplimiento (%)', compute='_compute_result', store=True)
    bonus_max_usd = fields.Monetary(
        string='Bono máximo (USD)', currency_field='currency_id', default=0.0)
    bonus_usd = fields.Monetary(
        string='Bono a pagar (USD)', currency_field='currency_id',
        compute='_compute_result', store=True)
    currency_id = fields.Many2one(
        'res.currency', default=lambda self: self.env.ref('base.USD', raise_if_not_found=False))
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('confirmed', 'Confirmada'),
    ], string='Estado', default='draft', required=True)
    notes = fields.Text(string='Observaciones')
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)

    @api.depends('employee_id', 'period_id')
    def _compute_name(self):
        for evaluation in self:
            evaluation.name = '%s — %s' % (
                evaluation.employee_id.name or '',
                evaluation.period_id.name or '')

    @api.depends('line_ids.weighted_score', 'line_ids.weight', 'bonus_max_usd')
    def _compute_result(self):
        for evaluation in self:
            weight = sum(evaluation.line_ids.mapped('weight'))
            if weight:
                evaluation.result_pct = sum(
                    evaluation.line_ids.mapped('weighted_score')) / weight
            else:
                evaluation.result_pct = 0.0
            evaluation.bonus_usd = evaluation.bonus_max_usd * evaluation.result_pct / 100.0

    def _get_effective_job(self):
        self.ensure_one()
        line = self.env['venrides.rotation.line'].search([
            ('employee_id', '=', self.employee_id.id),
            ('date_start', '<=', self.period_id.date_to),
            ('date_end', '>=', self.period_id.date_to),
        ], order='date_start desc', limit=1)
        return line.job_id or self.contract_id.job_id

    def action_load_goals(self):
        for evaluation in self:
            evaluation.job_id = evaluation._get_effective_job()
            goals = evaluation.period_id.goal_ids.filtered(
                lambda g: g.scope == 'global'
                or (g.scope == 'job' and g.job_id == evaluation.job_id)
                or (g.scope == 'individual' and g.employee_id == evaluation.employee_id))
            evaluation.line_ids.unlink()
            evaluation.write({'line_ids': [(0, 0, {
                'goal_id': goal.id,
                'name': goal.name,
                'scope': goal.scope,
                'weight': goal.weight,
                'target': goal.target,
                'achieved': goal.achieved,
            }) for goal in goals]})
            if evaluation.contract_id:
                days = (evaluation.period_id.date_to - evaluation.period_id.date_from).days + 1
                evaluation.bonus_max_usd = (
                    evaluation.contract_id.bono_desempeno_max_usd * days / 30.0)
        return True

    def action_confirm(self):
        for evaluation in self:
            if not evaluation.line_ids:
                raise UserError('Carga las metas antes de confirmar la evaluación.')
            evaluation.state = 'confirmed'
        return True


class VenridesPerformanceEvaluationLine(models.Model):
    _name = 'venrides.performance.evaluation.line'
    _description = 'Línea de evaluación'
    _order = 'evaluation_id, scope, id'

    evaluation_id = fields.Many2one(
        'venrides.performance.evaluation', string='Evaluación',
        required=True, ondelete='cascade')
    goal_id = fields.Many2one('venrides.performance.goal', string='Meta')
    name = fields.Char(string='Meta', required=True)
    scope = fields.Selection([
        ('global', 'Global'),
        ('job', 'Del puesto'),
        ('individual', 'Individual'),
    ], string='Ámbito', required=True)
    weight = fields.Float(string='Peso', default=100.0)
    target = fields.Float(string='Meta', default=100.0)
    achieved = fields.Float(string='Resultado', default=0.0)
    score = fields.Float(string='Cumplimiento (%)', compute='_compute_score', store=True)
    weighted_score = fields.Float(string='Aporte', compute='_compute_score', store=True)

    @api.depends('target', 'achieved', 'weight')
    def _compute_score(self):
        for line in self:
            line.score = min(line.achieved / line.target, 1.0) * 100.0 if line.target else 0.0
            line.weighted_score = line.score * line.weight
