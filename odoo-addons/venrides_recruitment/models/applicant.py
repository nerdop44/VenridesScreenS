# -*- coding: utf-8 -*-
import re

from odoo import api, fields, models


MARITAL_STATUS = [
    ('single', 'Soltero(a)'),
    ('married', 'Casado(a)'),
    ('concubine', 'Concubino(a)'),
    ('divorced', 'Divorciado(a)'),
    ('widowed', 'Viudo(a)'),
]

EDUCATION_LEVEL = [
    ('none', 'Sin instrucción'),
    ('primary', 'Primaria'),
    ('secondary', 'Bachiller'),
    ('technical', 'Técnico medio'),
    ('university', 'Universitario'),
    ('postgraduate', 'Postgrado'),
]

SOURCE_CHANNEL = [
    ('web', 'Formulario web'),
    ('whatsapp', 'WhatsApp'),
    ('email', 'Correo'),
    ('referral', 'Referido'),
    ('walkin', 'Presencial'),
    ('other', 'Otro'),
]


class HrApplicant(models.Model):
    _inherit = 'hr.applicant'

    vacancy_id = fields.Many2one('venrides.vacancy', string='Vacante', tracking=True, index=True)
    national_id = fields.Char(string='Cédula de identidad', index=True)
    birthdate = fields.Date(string='Fecha de nacimiento')
    home_address = fields.Text(string='Dirección de habitación')
    marital_status = fields.Selection(MARITAL_STATUS, string='Estado civil')
    dependents = fields.Integer(string='Cargas familiares', default=0)
    education_level = fields.Selection(EDUCATION_LEVEL, string='Nivel educativo')
    consent_privacy = fields.Boolean(string='Consentimiento de datos personales')
    consent_date = fields.Datetime(string='Fecha de consentimiento')
    source_channel = fields.Selection(SOURCE_CHANNEL, string='Canal de origen', default='web')
    form_token = fields.Char(string='Token de consulta', copy=False, index=True)
    photo = fields.Binary(string='Foto del postulante', attachment=True, copy=False)
    photo_date = fields.Datetime(string='Fecha de la foto', copy=False)

    education_ids = fields.One2many(
        'venrides.applicant.education', 'applicant_id', string='Formación académica')
    experience_ids = fields.One2many(
        'venrides.applicant.experience', 'applicant_id', string='Experiencia laboral')
    reference_ids = fields.One2many(
        'venrides.applicant.reference', 'applicant_id', string='Referencias')
    test_invitation_ids = fields.One2many(
        'venrides.test.invitation', 'applicant_id', string='Invitaciones a test')
    test_attempt_ids = fields.One2many(
        'venrides.test.attempt', 'applicant_id', string='Intentos de test')
    phase_ids = fields.One2many(
        'venrides.selection.phase', 'applicant_id', string='Fases de selección')
    document_ids = fields.One2many(
        'venrides.employee.document', 'applicant_id', string='Documentos')

    test_score = fields.Float(string='Puntaje del test', compute='_compute_test_result', store=True)
    test_max_score = fields.Float(string='Puntaje máximo', compute='_compute_test_result', store=True)
    test_percentage = fields.Float(string='% del test', compute='_compute_test_result', store=True)
    test_state = fields.Selection([
        ('none', 'Sin test'),
        ('draft', 'Borrador'),
        ('pending', 'Pendiente'),
        ('sent', 'Enviado'),
        ('opened', 'Abierto'),
        ('done', 'Finalizado'),
        ('expired', 'Vencido'),
        ('cancelled', 'Cancelado'),
    ], string='Estado del test', compute='_compute_test_state', store=True)
    test_url = fields.Char(string='Enlace del test', compute='_compute_test_url')
    whatsapp_url = fields.Char(string='Enlace WhatsApp', compute='_compute_whatsapp_url')

    def _get_last_attempt(self):
        self.ensure_one()
        return self.test_attempt_ids.filtered(
            lambda a: a.state == 'done').sorted('date_end', reverse=True)[:1]

    @api.depends('test_attempt_ids.state', 'test_attempt_ids.score',
                 'test_attempt_ids.max_score', 'test_attempt_ids.percentage')
    def _compute_test_result(self):
        for applicant in self:
            attempt = applicant._get_last_attempt()
            applicant.test_score = attempt.score if attempt else 0.0
            applicant.test_max_score = attempt.max_score if attempt else 0.0
            applicant.test_percentage = attempt.percentage if attempt else 0.0

    @api.depends('test_attempt_ids.state', 'test_invitation_ids.state')
    def _compute_test_state(self):
        for applicant in self:
            if applicant._get_last_attempt():
                applicant.test_state = 'done'
                continue
            if not applicant.test_invitation_ids:
                applicant.test_state = 'none'
                continue
            invitation = applicant.test_invitation_ids.sorted('id', reverse=True)[:1]
            applicant.test_state = invitation.state

    def _compute_test_url(self):
        base = self.env['ir.config_parameter'].sudo().get_str('web.base.url', '')
        for applicant in self:
            invitation = applicant.test_invitation_ids.sorted('id', reverse=True)[:1]
            applicant.test_url = (
                '%s/test/%s' % (base.rstrip('/'), invitation.token)
                if invitation and invitation.token else False)

    def _compute_whatsapp_url(self):
        for applicant in self:
            phone = re.sub(r'\D', '', applicant.partner_phone or '')
            if phone.startswith('0'):
                phone = '58' + phone[1:]
            elif len(phone) == 10 and phone.startswith('4'):
                phone = '58' + phone
            if not phone:
                applicant.whatsapp_url = False
                continue
            text = 'Hola %s, gracias por postular a %s. Completa tu test en: %s' % (
                applicant.partner_name or '',
                applicant.vacancy_id.name or applicant.job_id.name or 'nuestra vacante',
                applicant.test_url or '')
            from urllib.parse import quote
            applicant.whatsapp_url = 'https://wa.me/%s?text=%s' % (phone, quote(text))

    def create_employee_from_applicant(self):
        action = super().create_employee_from_applicant()
        for applicant in self:
            employee = applicant.employee_id
            if not employee:
                continue
            if applicant.photo:
                employee.image_1920 = applicant.photo.to_base64()
            applicant.document_ids.write({'employee_id': employee.id})
        return action

    def action_create_test_invitation(self):
        self.ensure_one()
        template = self.vacancy_id.test_template_id
        if not template:
            template = self.job_id.venrides_test_template_id
        if not template:
            from odoo.exceptions import UserError
            raise UserError('La vacante o el puesto no tienen un test de selección configurado.')
        invitation = self.test_invitation_ids.filtered(
            lambda i: i.state in ('draft', 'sent', 'opened')).sorted('id', reverse=True)[:1]
        if not invitation:
            invitation = self.env['venrides.test.invitation'].create({
                'applicant_id': self.id,
                'template_id': template.id,
                'channel': 'whatsapp' if self.source_channel == 'whatsapp' else 'email',
            })
        return {
            'type': 'ir.actions.act_window',
            'name': 'Invitación al test',
            'res_model': 'venrides.test.invitation',
            'res_id': invitation.id,
            'view_mode': 'form',
            'target': 'current',
        }

    def action_send_test_email(self):
        for applicant in self:
            invitation = applicant.test_invitation_ids.filtered(
                lambda i: i.state in ('draft', 'sent', 'opened')).sorted('id', reverse=True)[:1]
            if not invitation:
                applicant.action_create_test_invitation()
                invitation = applicant.test_invitation_ids.sorted('id', reverse=True)[:1]
            if invitation:
                invitation.action_send_email()

    def action_open_whatsapp(self):
        self.ensure_one()
        if not self.whatsapp_url:
            from odoo.exceptions import UserError
            raise UserError('El postulante no tiene un teléfono válido registrado.')
        return {
            'type': 'ir.actions.act_url',
            'url': self.whatsapp_url,
            'target': 'new',
        }


class HrJob(models.Model):
    _inherit = 'hr.job'

    venrides_test_template_id = fields.Many2one(
        'venrides.test.template', string='Test de selección por defecto')
    venrides_area = fields.Selection([
        ('atc', 'ATC'),
        ('general', 'Ayudante general'),
        ('kitchen', 'Cocina'),
        ('other', 'Otro'),
    ], string='Área de selección', default='other')
