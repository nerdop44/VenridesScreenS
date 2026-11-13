# -*- coding: utf-8 -*-
import secrets
from datetime import timedelta
from urllib.parse import quote

from odoo import api, fields, models


class VenridesApplicationLink(models.Model):
    _name = 'venrides.application.link'
    _description = 'Enlace único de postulación y tests'
    _inherit = ['mail.thread']
    _order = 'create_date desc, id desc'

    name = fields.Char(string='Referencia', compute='_compute_name', store=True)
    token = fields.Char(
        string='Token', required=True, copy=False, index=True,
        default=lambda self: secrets.token_urlsafe(32))
    state = fields.Selection([
        ('new', 'Nuevo'),
        ('opened', 'Abierto'),
        ('submitted', 'Enviado'),
        ('expired', 'Vencido'),
        ('cancelled', 'Cancelado'),
    ], string='Estado', default='new', required=True, copy=False)
    expiry_date = fields.Date(
        string='Vence', default=lambda self: fields.Date.context_today(self) + timedelta(days=7))
    vacancy_id = fields.Many2one(
        'venrides.vacancy', string='Vacante (opcional)',
        help='Si se indica, el postulante no elige el puesto.')
    template_ids = fields.Many2many(
        'venrides.test.template', 'venrides_application_link_test_rel',
        'link_id', 'template_id', string='Tests a aplicar',
        help='Si se deja vacío, se aplican los 3 tests activos.')
    applicant_id = fields.Many2one('hr.applicant', string='Postulante', copy=False)
    recipient_name = fields.Char(string='Nombre del destinatario')
    recipient_email = fields.Char(
        string='Correo del destinatario',
        default=lambda self: self.env.user.email or '')
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)
    opened_date = fields.Datetime(string='Abierto', copy=False)
    submitted_date = fields.Datetime(string='Enviado', copy=False)
    url = fields.Char(string='Enlace', compute='_compute_url')
    whatsapp_url = fields.Char(string='Enviar por WhatsApp', compute='_compute_whatsapp_url')

    _token_uniq = models.Constraint(
        'unique(token)', 'El token del enlace debe ser único.')

    @api.depends('token', 'recipient_name', 'vacancy_id')
    def _compute_name(self):
        for link in self:
            link.name = 'Enlace — %s' % (
                link.recipient_name or link.vacancy_id.name or (link.token or '')[:8])

    def _compute_url(self):
        base = self.env['ir.config_parameter'].sudo().get_str('web.base.url', '')
        for link in self:
            link.url = '%s/proceso/%s' % (base.rstrip('/'), link.token)

    def _compute_whatsapp_url(self):
        for link in self:
            text = (
                'Hola%s, para completar tu postulación en VenridesCafé entra a este enlace: %s '
                'Debes llenar tus datos y realizar los 3 tests.' % (
                    (' ' + link.recipient_name) if link.recipient_name else '',
                    link.url or ''))
            link.whatsapp_url = 'https://wa.me/?text=%s' % quote(text)

    def action_open_link(self):
        self.ensure_one()
        return {'type': 'ir.actions.act_url', 'url': self.url, 'target': 'new'}

    def action_send_email(self):
        for link in self:
            email = link.recipient_email
            if not email:
                from odoo.exceptions import UserError
                raise UserError('Indica el correo del destinatario.')
            body = (
                '<div style="font-family:Arial,sans-serif;color:#3b2b2b;">'
                '<h2 style="color:#6E161E;">VenridesCafé — Postulación</h2>'
                '<p>Hola%s:</p>'
                '<p>Completa tu postulación y los 3 tests en este enlace:</p>'
                '<p><a href="%s">%s</a></p>'
                '<p>Debes llenar tus datos personales, tu síntesis curricular y realizar '
                'los tests de ATC, Ayudante general y Cocina.</p>'
                '</div>' % (
                    (' ' + link.recipient_name) if link.recipient_name else '',
                    link.url, link.url))
            mail = self.env['mail.mail'].sudo().create({
                'subject': 'VScreenS — Completa tu postulación y tests',
                'email_to': email,
                'email_from': link.company_id.email or 'no-reply@inverpave.com',
                'body_html': body,
            })
            try:
                mail.send()
            except Exception:  # noqa: BLE001
                pass
            link.message_post(body='Enlace enviado a %s.' % email)
        return True

    def action_cancel(self):
        self.write({'state': 'cancelled'})
