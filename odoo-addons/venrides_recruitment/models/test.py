# -*- coding: utf-8 -*-
import secrets
from datetime import timedelta

from odoo import api, fields, models
from odoo.exceptions import UserError


TEST_AREAS = [
    ('atc', 'ATC (atención al cliente)'),
    ('general', 'Ayudante general'),
    ('kitchen', 'Cocina'),
    ('other', 'General'),
]


class VenridesTestTemplate(models.Model):
    _name = 'venrides.test.template'
    _description = 'Plantilla de test de selección'
    _order = 'sequence, id'

    name = fields.Char(string='Nombre', required=True)
    code = fields.Char(string='Código', required=True)
    area = fields.Selection(TEST_AREAS, string='Área', required=True, default='other')
    version = fields.Char(string='Versión', default='1.0')
    instructions = fields.Html(string='Instrucciones')
    duration_minutes = fields.Integer(string='Duración (minutos)', default=30)
    pass_score = fields.Float(
        string='Puntaje de referencia (%)', default=60.0,
        help='Valor informativo. El test no es limitativo: no rechaza automáticamente.')
    question_ids = fields.One2many(
        'venrides.test.question', 'template_id', string='Preguntas')
    question_count = fields.Integer(compute='_compute_question_count')
    max_score = fields.Float(string='Puntaje máximo', compute='_compute_max_score')
    active = fields.Boolean(default=True)
    sequence = fields.Integer(default=10)

    _code_uniq = models.Constraint(
        'unique(code)', 'El código del test debe ser único.')

    @api.depends('question_ids')
    def _compute_question_count(self):
        for template in self:
            template.question_count = len(template.question_ids)

    @api.depends('question_ids.weight')
    def _compute_max_score(self):
        for template in self:
            template.max_score = sum(template.question_ids.mapped('weight'))


class VenridesTestQuestion(models.Model):
    _name = 'venrides.test.question'
    _description = 'Pregunta de test'
    _order = 'template_id, sequence, id'

    template_id = fields.Many2one(
        'venrides.test.template', string='Test', required=True, ondelete='cascade')
    sequence = fields.Integer(default=10)
    name = fields.Text(string='Pregunta', required=True)
    question_type = fields.Selection([
        ('single', 'Selección única'),
        ('multiple', 'Selección múltiple'),
        ('boolean', 'Verdadero / Falso'),
    ], string='Tipo', default='single', required=True)
    weight = fields.Float(string='Peso', default=1.0)
    help_text = fields.Char(string='Ayuda')
    option_ids = fields.One2many(
        'venrides.test.option', 'question_id', string='Opciones')
    active = fields.Boolean(default=True)

    @api.constrains('question_type', 'option_ids')
    def _check_options(self):
        for question in self:
            if question.question_type == 'boolean' and len(question.option_ids) not in (0, 2):
                raise UserError('Las preguntas de Verdadero/Falso deben tener exactamente dos opciones.')
            if question.question_type == 'single':
                correct = question.option_ids.filtered('is_correct')
                if len(correct) > 1:
                    raise UserError('Una pregunta de selección única solo puede tener una respuesta correcta.')


class VenridesTestOption(models.Model):
    _name = 'venrides.test.option'
    _description = 'Opción de respuesta'
    _order = 'question_id, sequence, id'

    question_id = fields.Many2one(
        'venrides.test.question', string='Pregunta', required=True, ondelete='cascade')
    sequence = fields.Integer(default=10)
    name = fields.Char(string='Opción', required=True)
    is_correct = fields.Boolean(string='Correcta')
    active = fields.Boolean(default=True)


class VenridesTestInvitation(models.Model):
    _name = 'venrides.test.invitation'
    _description = 'Invitación a test'
    _order = 'id desc'

    name = fields.Char(string='Referencia', compute='_compute_name', store=True)
    token = fields.Char(
        string='Token', required=True, copy=False, index=True,
        default=lambda self: secrets.token_urlsafe(24))
    applicant_id = fields.Many2one(
        'hr.applicant', string='Postulante', required=True, ondelete='cascade')
    template_id = fields.Many2one(
        'venrides.test.template', string='Test', required=True)
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('sent', 'Enviada'),
        ('opened', 'Abierta'),
        ('done', 'Finalizada'),
        ('expired', 'Vencida'),
        ('cancelled', 'Cancelada'),
    ], string='Estado', default='draft', required=True, copy=False)
    channel = fields.Selection([
        ('email', 'Correo'),
        ('whatsapp', 'WhatsApp'),
        ('manual', 'Manual'),
    ], string='Canal', default='email')
    sent_date = fields.Datetime(string='Fecha de envío')
    opened_date = fields.Datetime(string='Fecha de apertura')
    submitted_date = fields.Datetime(string='Fecha de finalización')
    expiry_date = fields.Date(
        string='Vence', default=lambda self: fields.Date.context_today(self) + timedelta(days=7))
    attempt_ids = fields.One2many(
        'venrides.test.attempt', 'invitation_id', string='Intentos')
    attempt_count = fields.Integer(compute='_compute_attempt_count')
    url = fields.Char(string='Enlace', compute='_compute_url')
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)

    _token_uniq = models.Constraint(
        'unique(token)', 'El token de la invitación debe ser único.')

    @api.depends('applicant_id', 'template_id')
    def _compute_name(self):
        for invitation in self:
            invitation.name = '%s — %s' % (
                invitation.applicant_id.partner_name or 'Postulante',
                invitation.template_id.name or 'Test')

    @api.depends('attempt_ids')
    def _compute_attempt_count(self):
        for invitation in self:
            invitation.attempt_count = len(invitation.attempt_ids)

    def _compute_url(self):
        base = self.env['ir.config_parameter'].sudo().get_str('web.base.url', '')
        for invitation in self:
            invitation.url = '%s/test/%s' % (base.rstrip('/'), invitation.token)

    def action_send_email(self):
        self.ensure_one()
        if not self.applicant_id.email_from:
            raise UserError('El postulante no tiene correo registrado.')
        if not self.expiry_date:
            self.expiry_date = fields.Date.context_today(self) + timedelta(days=7)
        template = self.env.ref(
            'venrides_recruitment.mail_template_test', raise_if_not_found=False)
        if not template:
            raise UserError('No se encontró la plantilla de correo del test.')
        template.sudo().send_mail(self.id, force_send=True, email_values={
            'email_to': self.applicant_id.email_from,
        })
        self.write({'state': 'sent', 'sent_date': fields.Datetime.now()})

    def action_open_link(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_url',
            'url': self.url,
            'target': 'new',
        }

    def action_mark_expired(self):
        today = fields.Date.context_today(self)
        self.filtered(
            lambda i: i.state in ('sent', 'opened') and i.expiry_date
            and i.expiry_date < today).write({'state': 'expired'})


class VenridesTestAttempt(models.Model):
    _name = 'venrides.test.attempt'
    _description = 'Intento de test'
    _order = 'id desc'

    name = fields.Char(string='Referencia', compute='_compute_name', store=True)
    invitation_id = fields.Many2one(
        'venrides.test.invitation', string='Invitación', required=True, ondelete='cascade')
    applicant_id = fields.Many2one(
        'hr.applicant', string='Postulante', related='invitation_id.applicant_id',
        store=True, index=True)
    template_id = fields.Many2one(
        'venrides.test.template', string='Test', related='invitation_id.template_id',
        store=True)
    date_start = fields.Datetime(string='Inicio', default=fields.Datetime.now)
    date_end = fields.Datetime(string='Fin')
    duration_minutes = fields.Float(string='Duración (min)', compute='_compute_duration', store=True)
    state = fields.Selection([
        ('in_progress', 'En curso'),
        ('done', 'Finalizado'),
        ('cancelled', 'Cancelado'),
    ], string='Estado', default='in_progress', required=True)
    score = fields.Float(string='Puntaje', default=0.0)
    max_score = fields.Float(string='Máximo', default=0.0)
    percentage = fields.Float(string='Porcentaje', compute='_compute_percentage', store=True)
    line_ids = fields.One2many('venrides.test.attempt.line', 'attempt_id', string='Respuestas')
    ip_address = fields.Char(string='IP')
    user_agent = fields.Char(string='Navegador')
    company_id = fields.Many2one('res.company', default=lambda self: self.env.company)

    @api.depends('applicant_id', 'template_id', 'date_start')
    def _compute_name(self):
        for attempt in self:
            attempt.name = '%s — %s — %s' % (
                attempt.applicant_id.partner_name or 'Postulante',
                attempt.template_id.name or 'Test',
                attempt.date_start or '')

    @api.depends('date_start', 'date_end')
    def _compute_duration(self):
        for attempt in self:
            if attempt.date_start and attempt.date_end:
                delta = attempt.date_end - attempt.date_start
                attempt.duration_minutes = delta.total_seconds() / 60.0
            else:
                attempt.duration_minutes = 0.0

    @api.depends('score', 'max_score')
    def _compute_percentage(self):
        for attempt in self:
            attempt.percentage = (attempt.score / attempt.max_score * 100.0) if attempt.max_score else 0.0


class VenridesTestAttemptLine(models.Model):
    _name = 'venrides.test.attempt.line'
    _description = 'Respuesta de test'
    _order = 'attempt_id, question_id'

    attempt_id = fields.Many2one(
        'venrides.test.attempt', string='Intento', required=True, ondelete='cascade')
    question_id = fields.Many2one(
        'venrides.test.question', string='Pregunta', required=True)
    selected_option_ids = fields.Many2many(
        'venrides.test.option', 'venrides_attempt_line_option_rel',
        'line_id', 'option_id', string='Opciones seleccionadas')
    is_correct = fields.Boolean(string='Correcta')
    score = fields.Float(string='Puntaje obtenido')
    max_score = fields.Float(string='Puntaje máximo')
    answer_text = fields.Text(string='Respuesta abierta')
