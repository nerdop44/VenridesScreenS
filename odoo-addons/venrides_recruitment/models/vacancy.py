# -*- coding: utf-8 -*-
from odoo import api, fields, models


class VenridesVacancy(models.Model):
    _name = 'venrides.vacancy'
    _description = 'Vacante'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _order = 'sequence, id desc'

    name = fields.Char(string='Vacante', required=True, tracking=True)
    code = fields.Char(string='Código', required=True, default='NUEVA')
    job_id = fields.Many2one('hr.job', string='Puesto', required=True, tracking=True)
    department_id = fields.Many2one(
        'hr.department', string='Departamento',
        related='job_id.department_id', store=True, readonly=True)
    company_id = fields.Many2one(
        'res.company', string='Compañía', required=True,
        default=lambda self: self.env.company)
    slots = fields.Integer(string='Cupos', default=1, tracking=True)
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('open', 'Publicada'),
        ('closed', 'Cerrada'),
    ], string='Estado', default='draft', required=True, tracking=True)
    date_open = fields.Date(string='Fecha de apertura', default=fields.Date.context_today)
    date_close = fields.Date(string='Fecha de cierre')
    schedule_description = fields.Char(
        string='Horario', default='Lunes a viernes 7:30 am - 5:00 pm · '
                                  'un sábado 7:30 am - 3:00 pm cada 3 sábados')
    salary_summary = fields.Char(
        string='Resumen salarial',
        help='Texto informativo que se muestra en la web. No reemplaza la tabla salarial.')
    description = fields.Html(string='Descripción del cargo')
    requirements = fields.Html(string='Requisitos')
    test_template_id = fields.Many2one(
        'venrides.test.template', string='Test de selección',
        domain="[('active', '=', True)]")
    sequence = fields.Integer(default=10)
    active = fields.Boolean(default=True)
    application_ids = fields.One2many('hr.applicant', 'vacancy_id', string='Postulaciones')
    application_count = fields.Integer(compute='_compute_application_count')
    public_url = fields.Char(string='URL pública', compute='_compute_public_url')
    whatsapp_share_url = fields.Char(
        string='Compartir por WhatsApp', compute='_compute_whatsapp_share_url')

    _code_uniq = models.Constraint(
        'unique(code)', 'El código de la vacante debe ser único.')

    @api.depends('application_ids')
    def _compute_application_count(self):
        for vacancy in self:
            vacancy.application_count = len(vacancy.application_ids)

    def _compute_public_url(self):
        base = self.env['ir.config_parameter'].sudo().get_str('web.base.url', '')
        for vacancy in self:
            vacancy.public_url = '%s/empleo/%s' % (base.rstrip('/'), vacancy.id)

    def _compute_whatsapp_share_url(self):
        from urllib.parse import quote
        for vacancy in self:
            text = 'Estamos contratando: %s. Postúlate aquí: %s' % (
                vacancy.name or '', vacancy.public_url or '')
            vacancy.whatsapp_share_url = 'https://wa.me/?text=%s' % quote(text)

    def action_share_whatsapp(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_url',
            'url': self.whatsapp_share_url,
            'target': 'new',
        }

    def action_publish(self):
        self.write({'state': 'open'})

    def action_close(self):
        self.write({'state': 'closed'})

    def action_open_applications(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Postulaciones — %s' % self.name,
            'res_model': 'hr.applicant',
            'view_mode': 'kanban,list,form',
            'domain': [('vacancy_id', '=', self.id)],
            'context': {'default_vacancy_id': self.id, 'default_job_id': self.job_id.id},
        }
