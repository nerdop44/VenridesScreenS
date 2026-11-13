# -*- coding: utf-8 -*-
import base64
import hashlib
import secrets
from datetime import timedelta

from markupsafe import Markup

from odoo import api, fields, models
from odoo.exceptions import UserError, ValidationError


CONTRACT_STAGES = [
    ('trial', 'Periodo de prueba (30 días)'),
    ('90', 'Inicial (90 días)'),
    ('180', 'Renovación (180 días)'),
    ('1y', 'Anual (1 año)'),
    ('indefinite', 'Indefinido / prórroga'),
]

STAGE_DAYS = {
    'trial': 30,
    '90': 90,
    '180': 180,
    '1y': 365,
    'indefinite': 0,
}

SIGNATURE_STATES = [
    ('draft', 'Borrador'),
    ('sent', 'Enviado'),
    ('otp_sent', 'Código enviado'),
    ('signed', 'Firmado'),
    ('declined', 'Rechazado'),
    ('expired', 'Vencido'),
]


class HrContract(models.Model):
    _inherit = 'hr.contract'

    contract_number = fields.Char(string='Número de contrato', copy=False, index=True)
    job_id = fields.Many2one('hr.job', string='Puesto')
    department_id = fields.Many2one(
        'hr.department', string='Departamento', related='job_id.department_id',
        store=True, readonly=True)
    contract_stage = fields.Selection(
        CONTRACT_STAGES, string='Etapa del contrato', default='trial', required=True)
    parent_contract_id = fields.Many2one(
        'hr.contract', string='Contrato anterior', copy=False, index=True)
    child_contract_ids = fields.One2many(
        'hr.contract', 'parent_contract_id', string='Contratos posteriores')
    duration_days = fields.Integer(
        string='Duración (días)', compute='_compute_duration_days', store=True)
    renewal_due = fields.Boolean(
        string='Por renovar', compute='_compute_renewal_due', store=True)
    contract_stage_label = fields.Char(
        string='Etapa', compute='_compute_contract_stage_label')

    template_id = fields.Many2one(
        'venrides.contract.template', string='Plantilla / versión')
    rendered_body = fields.Html(
        string='Cuerpo renderizado', compute='_compute_rendered_body')
    annex_ids = fields.Many2many(
        'venrides.contract.annex', 'venrides_contract_annex_rel',
        'contract_id', 'annex_id', string='Anexos')
    salary_table_id = fields.Many2one(
        'venrides.salary.table', string='Tabla salarial')
    salary_table_line_id = fields.Many2one(
        'venrides.salary.table.line', string='Línea de tabla salarial')
    bono_guerra_usd = fields.Monetary(
        string='Bono de guerra (USD)', currency_field='currency_id_dif', default=0.0)
    bono_transporte_usd = fields.Monetary(
        string='Bono transporte/asistencia (USD)', currency_field='currency_id_dif',
        default=0.0)
    bono_desempeno_max_usd = fields.Monetary(
        string='Bono desempeño máximo (USD)', currency_field='currency_id_dif',
        default=0.0)
    cestaticket_usd = fields.Monetary(
        string='Cestatickets (USD)', currency_field='currency_id_dif', default=0.0)
    total_package_usd = fields.Monetary(
        string='Paquete mensual referencial (USD)', currency_field='currency_id_dif',
        compute='_compute_total_package', store=True)
    schedule_description = fields.Char(
        string='Jornada',
        default='Lunes a viernes 7:30 am - 5:00 pm · '
                'un sábado 7:30 am - 3:00 pm cada 3 sábados')

    signature_state = fields.Selection(
        SIGNATURE_STATES, string='Estado de firma', default='draft', copy=False)
    signature_method = fields.Selection([
        ('canvas', 'Firma digital en pantalla'),
        ('physical', 'Firma física escaneada'),
        ('external', 'Firma electrónica externa'),
    ], string='Método de firma', copy=False)
    signature_token = fields.Char(string='Token de firma', copy=False, index=True)
    signature_url = fields.Char(string='Enlace de firma', compute='_compute_signature_url')
    signer_email = fields.Char(string='Correo del firmante')
    signed_date = fields.Datetime(string='Fecha de firma', copy=False)
    signed_pdf = fields.Binary(string='Contrato firmado (PDF)', attachment=True, copy=False)
    document_hash = fields.Char(string='Hash SHA-256', copy=False)
    signature_image = fields.Binary(string='Firma (imagen)', attachment=True, copy=False)
    signature_image_data = fields.Char(
        string='Firma (data URI)', compute='_compute_signature_image_data')
    signature_ip = fields.Char(string='IP de firma', copy=False)
    signature_user_agent = fields.Char(string='Navegador de firma', copy=False)
    signature_otp_hash = fields.Char(string='OTP (hash)', copy=False)
    signature_otp_expiry = fields.Datetime(string='OTP vence', copy=False)
    signature_otp_attempts = fields.Integer(string='Intentos OTP', default=0, copy=False)

    @api.depends('wage_usd', 'bono_guerra_usd', 'bono_transporte_usd',
                 'bono_desempeno_max_usd', 'cestaticket_usd')
    def _compute_total_package(self):
        for contract in self:
            contract.total_package_usd = (
                (contract.wage_usd or 0.0) + (contract.bono_guerra_usd or 0.0)
                + (contract.bono_transporte_usd or 0.0)
                + (contract.bono_desempeno_max_usd or 0.0)
                + (contract.cestaticket_usd or 0.0))

    @api.depends('date_start', 'date_end', 'contract_stage')
    def _compute_duration_days(self):
        for contract in self:
            if contract.date_start and contract.date_end:
                contract.duration_days = (contract.date_end - contract.date_start).days + 1
            else:
                contract.duration_days = 0

    @api.depends('contract_stage')
    def _compute_contract_stage_label(self):
        labels = dict(CONTRACT_STAGES)
        for contract in self:
            contract.contract_stage_label = labels.get(contract.contract_stage, '')

    @api.depends('date_end', 'state', 'contract_stage')
    def _compute_renewal_due(self):
        today = fields.Date.context_today(self)
        limit = today + timedelta(days=30)
        for contract in self:
            contract.renewal_due = bool(
                contract.date_end and contract.contract_stage != 'indefinite'
                and contract.state in ('open', 'pending')
                and today <= contract.date_end <= limit)

    @api.depends('template_id', 'wage_usd', 'bono_guerra_usd',
                 'bono_transporte_usd', 'bono_desempeno_max_usd', 'cestaticket_usd',
                 'date_start', 'date_end', 'job_id', 'employee_id')
    def _compute_rendered_body(self):
        for contract in self:
            contract.rendered_body = (
                contract.template_id._render_body(contract)
                if contract.template_id else Markup(''))

    def _compute_signature_url(self):
        base = self.env['ir.config_parameter'].sudo().get_str('web.base.url', '')
        for contract in self:
            contract.signature_url = (
                '%s/contrato/firmar/%s' % (base.rstrip('/'), contract.signature_token)
                if contract.signature_token else False)

    def _compute_signature_image_data(self):
        for contract in self:
            contract.signature_image_data = (
                'data:image/png;base64,%s' % contract.signature_image.to_base64()
                if contract.signature_image else False)

    @api.constrains('date_start', 'date_end')
    def _check_contract_dates(self):
        for contract in self:
            if contract.date_start and contract.date_end and contract.date_end < contract.date_start:
                raise ValidationError('La fecha de fin no puede ser anterior a la fecha de inicio.')

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if not vals.get('contract_number'):
                vals['contract_number'] = (
                    self.env['ir.sequence'].next_by_code('venrides.contract') or '/')
            if not vals.get('template_id') and vals.get('contract_type_id'):
                template = self.env['venrides.contract.template'].search([
                    ('contract_type_id', '=', vals['contract_type_id']),
                    ('is_current', '=', True),
                ], limit=1)
                if template:
                    vals['template_id'] = template.id
            if vals.get('template_id') and not vals.get('salary_table_id'):
                template = self.env['venrides.contract.template'].browse(vals['template_id'])
                if template.salary_table_id:
                    vals['salary_table_id'] = template.salary_table_id.id
            if vals.get('salary_table_id') and vals.get('job_id') and not vals.get('salary_table_line_id'):
                line = self.env['venrides.salary.table.line'].search([
                    ('table_id', '=', vals['salary_table_id']),
                    ('job_id', '=', vals['job_id']),
                ], limit=1)
                if line:
                    vals['salary_table_line_id'] = line.id
            if vals.get('salary_table_line_id'):
                line = self.env['venrides.salary.table.line'].browse(
                    vals['salary_table_line_id'])
                vals.setdefault('wage_usd', line.base_usd)
                vals.setdefault('basado_usd', True)
                vals.setdefault('bono_guerra_usd', line.bono_guerra_usd)
                vals.setdefault('bono_transporte_usd', line.bono_transporte_usd)
                vals.setdefault('bono_desempeno_max_usd', line.bono_desempeno_max_usd)
                vals.setdefault('cestaticket_usd', line.cestaticket_usd)
        return super().create(vals_list)

    @api.onchange('salary_table_id', 'job_id')
    def _onchange_salary_table(self):
        if self.salary_table_id and self.job_id:
            line = self.env['venrides.salary.table.line'].search([
                ('table_id', '=', self.salary_table_id.id),
                ('job_id', '=', self.job_id.id),
            ], limit=1)
            if line:
                self.salary_table_line_id = line
                self.wage_usd = line.base_usd
                self.bono_guerra_usd = line.bono_guerra_usd
                self.bono_transporte_usd = line.bono_transporte_usd
                self.bono_desempeno_max_usd = line.bono_desempeno_max_usd
                self.cestaticket_usd = line.cestaticket_usd

    @api.onchange('contract_stage', 'date_start')
    def _onchange_contract_stage(self):
        if self.date_start and self.contract_stage in STAGE_DAYS:
            days = STAGE_DAYS[self.contract_stage]
            self.date_end = (
                self.date_start + timedelta(days=days - 1) if days else False)

    def action_generate_signature_token(self):
        for contract in self:
            if not contract.signature_token:
                contract.signature_token = secrets.token_urlsafe(32)
        return True

    def action_send_signature_link(self):
        self.ensure_one()
        if not self.signer_email:
            self.signer_email = (
                self.employee_id.work_email or self.employee_id.private_email)
        if not self.signer_email:
            raise UserError('El empleado no tiene correo registrado. '
                            'Indica un correo de firma.')
        if not self.signature_token:
            self.action_generate_signature_token()
        template = self.env.ref(
            'venrides_hr_contracts.mail_template_signature', raise_if_not_found=False)
        if not template:
            raise UserError('No se encontró la plantilla de correo de firma.')
        template.sudo().send_mail(self.id, force_send=True, email_values={
            'email_to': self.signer_email,
        })
        self.write({'signature_state': 'sent'})
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': 'Enlace enviado',
                'message': 'Se envió el enlace de firma a %s.' % self.signer_email,
                'type': 'success',
            },
        }

    def action_open_signature_page(self):
        self.ensure_one()
        if not self.signature_token:
            self.action_generate_signature_token()
        return {
            'type': 'ir.actions.act_url',
            'url': self.signature_url,
            'target': 'new',
        }

    def action_mark_physical_signed(self):
        for contract in self:
            if not contract.signed_pdf:
                raise UserError('Debes cargar el PDF firmado antes de marcarlo como firmado.')
            pdf = bytes(contract.signed_pdf)
            contract.write({
                'signature_state': 'signed',
                'signature_method': 'physical',
                'signed_date': fields.Datetime.now(),
                'document_hash': hashlib.sha256(pdf).hexdigest(),
            })
        return True

    def _render_contract_pdf(self):
        self.ensure_one()
        pdf, _dummy = self.env['ir.actions.report'].sudo()._render_qweb_pdf(
            'venrides_hr_contracts.report_contract_document', res_ids=self.ids)
        return pdf

    def _sign_with_canvas(self, image_b64, ip=None, user_agent=None):
        """Firma el contrato con la imagen capturada en el portal."""
        self.ensure_one()
        if not image_b64:
            raise UserError('No se recibió la firma.')
        self.write({
            'signature_image': image_b64,
            'signature_method': 'canvas',
            'signature_state': 'signed',
            'signed_date': fields.Datetime.now(),
            'signature_ip': ip,
            'signature_user_agent': (user_agent or '')[:250],
            'signature_otp_hash': False,
            'signature_otp_expiry': False,
        })
        self.env.flush_all()
        pdf = self._render_contract_pdf()
        self.write({
            'signed_pdf': base64.b64encode(pdf).decode(),
            'document_hash': hashlib.sha256(pdf).hexdigest(),
        })
        self.env['venrides.contract.signature'].create({
            'contract_id': self.id,
            'signer_name': self.employee_id.name or self.employee_id.display_name,
            'signer_email': self.signer_email,
            'method': 'canvas',
            'state': 'signed',
            'verified_at': fields.Datetime.now(),
            'ip_address': ip,
            'user_agent': (user_agent or '')[:250],
            'image': image_b64,
            'document_hash': hashlib.sha256(pdf).hexdigest(),
        })
        return True

    def action_renew(self):
        self.ensure_one()
        if not self.date_end:
            raise UserError('Un contrato indefinido no requiere renovación.')
        return {
            'type': 'ir.actions.act_window',
            'name': 'Renovar contrato',
            'res_model': 'venrides.contract.renewal',
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_contract_id': self.id},
        }

    def action_view_child_contracts(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Contratos posteriores',
            'res_model': 'hr.contract',
            'view_mode': 'list,form',
            'domain': [('parent_contract_id', '=', self.id)],
            'context': {'default_parent_contract_id': self.id},
        }

    @api.model
    def _cron_contract_status(self):
        today = fields.Date.context_today(self)
        limit = today + timedelta(days=15)
        contracts = self.search([
            ('state', '=', 'open'),
            ('date_end', '!=', False),
            ('date_end', '<=', limit),
            ('date_end', '>=', today),
        ])
        contracts.write({'state': 'pending'})
        expired = self.search([
            ('state', 'in', ('open', 'pending')),
            ('date_end', '!=', False),
            ('date_end', '<', today),
        ])
        expired.write({'state': 'close'})
