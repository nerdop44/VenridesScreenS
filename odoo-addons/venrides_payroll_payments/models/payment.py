# -*- coding: utf-8 -*-
import base64

from odoo import api, fields, models
from odoo.exceptions import UserError


class VenridesPayrollPayment(models.Model):
    _name = 'venrides.payroll.payment'
    _description = 'Pago por concepto y recibo'
    _inherit = ['mail.thread']
    _order = 'payment_date desc, id desc'

    name = fields.Char(string='Recibo', copy=False, index=True)
    employee_id = fields.Many2one(
        'hr.employee', string='Empleado', required=True, index=True)
    contract_id = fields.Many2one('hr.contract', string='Contrato')
    concept_id = fields.Many2one(
        'venrides.pay.concept', string='Concepto', required=True)
    plan_id = fields.Many2one('venrides.pay.concept.plan', string='Plan de pago')
    payslip_id = fields.Many2one('hr.payslip', string='Recibo de nómina')
    payment_date = fields.Date(
        string='Fecha de pago', required=True, default=fields.Date.context_today)
    amount_usd = fields.Monetary(
        string='Monto (USD)', currency_field='currency_id', required=True)
    rate_bs_usd = fields.Float(string='Tasa oficial Bs/USD', digits=(16, 4), default=1.0)
    amount_bs = fields.Monetary(
        string='Monto (Bs)', currency_field='currency_id_bs',
        compute='_compute_amount_bs', store=True)
    currency_id = fields.Many2one(
        'res.currency', default=lambda self: self.env.ref('base.USD', raise_if_not_found=False))
    currency_id_bs = fields.Many2one(
        'res.currency', default=lambda self: self.env.ref('base.VES', raise_if_not_found=False))

    bank_support = fields.Binary(string='Soporte de abono', attachment=True, copy=False)
    bank_support_filename = fields.Char(string='Nombre del soporte')
    bank_reference = fields.Char(string='Referencia bancaria')
    sign_request_id = fields.Many2one(
        'venrides.sign.request', string='Solicitud de firma', copy=False)
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('sent', 'Enviado a firma'),
        ('signed', 'Firmado'),
        ('paid', 'Pagado'),
        ('void', 'Anulado'),
    ], string='Estado', default='draft', required=True, copy=False)
    notes = fields.Text(string='Notas')
    void_reason = fields.Text(string='Motivo de anulación', copy=False)
    void_date = fields.Datetime(string='Fecha de anulación', copy=False)
    duplicate_warning = fields.Boolean(
        string='Posible duplicado', compute='_compute_duplicate_warning')
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)

    @api.depends('employee_id', 'concept_id', 'payment_date', 'state')
    def _compute_duplicate_warning(self):
        for payment in self:
            payment.duplicate_warning = bool(
                payment.employee_id and payment.concept_id and payment.payment_date
                and self.search_count([
                    ('id', '!=', payment.id or 0),
                    ('employee_id', '=', payment.employee_id.id),
                    ('concept_id', '=', payment.concept_id.id),
                    ('payment_date', '=', payment.payment_date),
                    ('state', '!=', 'void'),
                ]))

    @api.depends('amount_usd', 'rate_bs_usd')
    def _compute_amount_bs(self):
        for payment in self:
            payment.amount_bs = (payment.amount_usd or 0.0) * (payment.rate_bs_usd or 0.0)

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if not vals.get('name'):
                vals['name'] = self.env['ir.sequence'].next_by_code(
                    'venrides.payroll.payment') or '/'
        return super().create(vals_list)

    @api.model
    def _get_bc_rate(self, date=None):
        date = date or fields.Date.context_today(self)
        ves = self.env['res.currency'].search([('name', '=', 'VES')], limit=1)
        if not ves:
            return 1.0
        rate = self.env['res.currency.rate'].search([
            ('currency_id', '=', ves.id),
            ('name', '<=', date),
        ], order='name desc', limit=1)
        return rate.rate or 1.0

    def _render_receipt_pdf(self, sign_request=None):
        self.ensure_one()
        pdf, _dummy = self.env['ir.actions.report'].sudo()._render_qweb_pdf(
            'venrides_payroll_payments.report_receipt', res_ids=self.ids)
        return pdf

    def _render_signed_receipt(self, sign_request):
        return self._render_receipt_pdf(sign_request)

    def action_create_receipt(self):
        for payment in self:
            if payment.sign_request_id and payment.sign_request_id.state == 'signed':
                continue
            email = payment.employee_id.work_email or payment.employee_id.private_email
            if not email:
                raise UserError(
                    'El empleado %s no tiene correo registrado. '
                    'Es necesario para enviar el recibo a firma.' % payment.employee_id.name)
            sign_request = payment.sign_request_id or self.env['venrides.sign.request'].create({
                'document_type': 'receipt',
                'employee_id': payment.employee_id.id,
                'signer_email': email,
                'reference': payment.name,
                'concept_name': payment.concept_id.name,
                'amount_usd': payment.amount_usd,
                'amount_bs': payment.amount_bs,
                'rate_bs_usd': payment.rate_bs_usd,
                'payment_date': payment.payment_date,
                'support': payment.bank_support,
                'support_filename': payment.bank_support_filename,
                'res_model': 'venrides.payroll.payment',
                'res_id': payment.id,
            })
            payment.write({'sign_request_id': sign_request.id, 'state': 'sent'})
            pdf = payment._render_receipt_pdf(sign_request)
            sign_request.write({'pdf_unsigned': base64.b64encode(pdf).decode()})
            sign_request.action_send()
        return True

    def _on_sign_request_signed(self, sign_request):
        self.ensure_one()
        self.write({'state': 'signed'})
        Document = self.env['venrides.employee.document']
        if not Document.search_count([
                ('payment_id', '=', self.id), ('doc_type', '=', 'receipt')]):
            attachment = self.env['ir.attachment'].create({
                'name': 'Recibo-%s.pdf' % (self.name or self.id),
                'raw': sign_request.pdf_signed.to_base64(),
                'res_model': 'venrides.sign.request',
                'res_id': sign_request.id,
                'mimetype': 'application/pdf',
            })
            Document.create({
                'name': 'Recibo firmado %s' % (self.name or ''),
                'doc_type': 'receipt',
                'employee_id': self.employee_id.id,
                'payment_id': self.id,
                'attachment_id': attachment.id,
                'date': self.payment_date,
                'verified': True,
            })
        if self.bank_support and not Document.search_count([
                ('payment_id', '=', self.id), ('doc_type', '=', 'payment_support')]):
            support = self.env['ir.attachment'].create({
                'name': self.bank_support_filename or 'soporte-abono',
                'raw': self.bank_support.to_base64(),
                'res_model': 'venrides.payroll.payment',
                'res_id': self.id,
            })
            Document.create({
                'name': 'Soporte de abono %s' % (self.name or ''),
                'doc_type': 'payment_support',
                'employee_id': self.employee_id.id,
                'payment_id': self.id,
                'attachment_id': support.id,
                'date': self.payment_date,
                'verified': True,
            })

    def action_mark_paid(self):
        self.write({'state': 'paid'})

    def action_void(self):
        for payment in self:
            if payment.state == 'paid':
                raise UserError('No se puede anular un pago ya marcado como pagado.')
            if payment.sign_request_id and payment.sign_request_id.state == 'signed':
                raise UserError(
                    'El recibo ya fue firmado. No se anula: emite un recibo de '
                    'reemplazo y conserva el firmado como evidencia.')
            if not payment.void_reason:
                raise UserError('Escribe el motivo de la anulación antes de continuar.')
            if payment.sign_request_id and payment.sign_request_id.state != 'signed':
                payment.sign_request_id.write({'state': 'declined'})
            payment.write({'state': 'void', 'void_date': fields.Datetime.now()})
        return True

    def action_reissue(self):
        self.ensure_one()
        new = self.copy({
            'name': False,
            'state': 'draft',
            'sign_request_id': False,
            'payment_date': fields.Date.context_today(self),
            'void_reason': False,
            'void_date': False,
            'bank_support': False,
            'bank_support_filename': False,
        })
        return {
            'type': 'ir.actions.act_window',
            'name': 'Recibo reemitido',
            'res_model': 'venrides.payroll.payment',
            'res_id': new.id,
            'view_mode': 'form',
            'target': 'current',
        }

    def action_view_sign_request(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Recibo para firma',
            'res_model': 'venrides.sign.request',
            'res_id': self.sign_request_id.id,
            'view_mode': 'form',
            'target': 'current',
        }
