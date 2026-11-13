# -*- coding: utf-8 -*-
import base64
import hashlib
import io
import json
import secrets
from datetime import timedelta

from PIL import Image, ImageChops

from odoo import api, fields, models
from odoo.exceptions import UserError, ValidationError


DOCUMENT_TYPES = [
    ('receipt', 'Recibo de pago'),
    ('medical', 'Reposo / justificativo médico'),
    ('other', 'Otro documento'),
]


class VenridesSignRequest(models.Model):
    _name = 'venrides.sign.request'
    _description = 'Solicitud de firma de documento'
    _inherit = ['mail.thread']
    _order = 'id desc'

    name = fields.Char(string='Referencia', compute='_compute_name', store=True)
    document_type = fields.Selection(
        DOCUMENT_TYPES, string='Tipo de documento', required=True, default='other')
    employee_id = fields.Many2one(
        'hr.employee', string='Empleado', required=True, ondelete='cascade')
    signer_email = fields.Char(string='Correo del firmante')
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)
    reference = fields.Char(string='Referencia del documento')
    concept_name = fields.Char(string='Concepto')
    amount_usd = fields.Monetary(
        string='Monto (USD)', currency_field='currency_id', default=0.0)
    amount_bs = fields.Monetary(
        string='Monto (Bs)', currency_field='currency_id_bs', default=0.0)
    rate_bs_usd = fields.Float(string='Tasa Bs/USD', digits=(16, 4), default=1.0)
    payment_date = fields.Date(string='Fecha de pago')
    currency_id = fields.Many2one(
        'res.currency', default=lambda self: self.env.ref('base.USD', raise_if_not_found=False))
    currency_id_bs = fields.Many2one(
        'res.currency', default=lambda self: self.env.ref('base.VES', raise_if_not_found=False))

    res_model = fields.Char(string='Modelo de origen')
    res_id = fields.Integer(string='ID de origen')

    token = fields.Char(
        string='Token', required=True, copy=False, index=True,
        default=lambda self: secrets.token_urlsafe(32))
    expiry_date = fields.Date(
        string='Vence', default=lambda self: fields.Date.context_today(self) + timedelta(days=7))
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('sent', 'Enviado'),
        ('otp_sent', 'Código enviado'),
        ('signed', 'Firmado'),
        ('declined', 'Rechazado'),
        ('expired', 'Vencido'),
    ], string='Estado', default='draft', required=True, copy=False)

    pdf_unsigned = fields.Binary(string='Documento a firmar', attachment=True, copy=False)
    pdf_signed = fields.Binary(string='Documento firmado', attachment=True, copy=False)
    support = fields.Binary(string='Soporte de abono / pago', attachment=True, copy=False)
    support_filename = fields.Char(string='Nombre del soporte')

    otp_hash = fields.Char(string='OTP (hash)', copy=False)
    otp_expiry = fields.Datetime(string='OTP vence', copy=False)
    otp_attempts = fields.Integer(string='Intentos OTP', default=0, copy=False)

    signed_date = fields.Datetime(string='Fecha de firma', copy=False)
    signature_image = fields.Binary(string='Firma', attachment=True, copy=False)
    signature_image_data = fields.Char(
        string='Firma (data URI)', compute='_compute_signature_image_data')
    signature_strokes = fields.Text(string='Trazos de la firma', copy=False)
    signature_point_count = fields.Integer(string='Puntos de la firma', copy=False)
    signature_duration_ms = fields.Integer(string='Duración de la firma (ms)', copy=False)
    signature_hash = fields.Char(string='Hash de la firma', copy=False)
    signature_dhash = fields.Char(string='dHash de la firma', copy=False)
    signature_similarity = fields.Float(string='Similitud con el contrato (%)', copy=False)
    signature_check = fields.Selection([
        ('ok', 'Verificada'),
        ('review', 'Revisar'),
        ('reject', 'Rechazada'),
        ('no_baseline', 'Sin firma de contrato'),
    ], string='Validación de firma', copy=False)
    signature_ip = fields.Char(string='IP de firma', copy=False)
    signature_user_agent = fields.Char(string='Navegador de firma', copy=False)

    content_hash = fields.Char(string='Hash del contenido', copy=False)
    signed_pdf_hash = fields.Char(string='Hash del PDF firmado', copy=False)

    sign_url = fields.Char(string='Enlace de firma', compute='_compute_urls')
    verify_url = fields.Char(string='Enlace de verificación', compute='_compute_urls')
    qr_url = fields.Char(string='QR', compute='_compute_urls')
    notes = fields.Text(string='Notas')
    state_label = fields.Char(string='Estado', compute='_compute_state_label')

    _token_uniq = models.Constraint(
        'unique(token)', 'El token de firma debe ser único.')

    @api.depends('state')
    def _compute_state_label(self):
        labels = dict(self._fields['state'].selection)
        for request in self:
            request.state_label = labels.get(request.state, '')

    @api.depends('document_type', 'employee_id', 'reference')
    def _compute_name(self):
        labels = dict(DOCUMENT_TYPES)
        for request in self:
            request.name = '%s — %s%s' % (
                labels.get(request.document_type, 'Documento'),
                request.employee_id.name or '',
                (' — %s' % request.reference) if request.reference else '')

    def _compute_urls(self):
        base = self.env['ir.config_parameter'].sudo().get_str('web.base.url', '')
        from urllib.parse import quote
        for request in self:
            request.sign_url = '%s/firma/%s' % (base.rstrip('/'), request.token)
            request.verify_url = '%s/firma/verificar/%s' % (base.rstrip('/'), request.token)
            request.qr_url = '%s/report/barcode/?barcode_type=QR&value=%s&width=120&height=120' % (
                base.rstrip('/'), quote(request.verify_url, safe=''))

    def _compute_signature_image_data(self):
        for request in self:
            request.signature_image_data = (
                'data:image/png;base64,%s' % request.signature_image.to_base64()
                if request.signature_image else False)

    # ------------------------------------------------------------------
    # Envío
    # ------------------------------------------------------------------
    def action_send(self):
        for request in self:
            if not request.signer_email:
                request.signer_email = (
                    request.employee_id.work_email or request.employee_id.private_email)
            if not request.signer_email:
                raise UserError('El empleado no tiene correo registrado.')
            template = self.env.ref(
                'venrides_hr_sign.mail_template_sign_request', raise_if_not_found=False)
            if not template:
                raise UserError('No se encontró la plantilla de correo de firma.')
            template.sudo().send_mail(request.id, force_send=True, email_values={
                'email_to': request.signer_email,
            })
            request.write({'state': 'sent'})
            request.message_post(body='Documento enviado a firma a %s.' % request.signer_email)
        return True

    def action_send_otp(self):
        self.ensure_one()
        code = '%06d' % secrets.randbelow(1000000)
        self.write({
            'otp_hash': hashlib.sha256(code.encode()).hexdigest(),
            'otp_expiry': fields.Datetime.now() + timedelta(minutes=10),
            'otp_attempts': 0,
            'state': 'otp_sent',
        })
        body = (
            '<div style="font-family:Arial,sans-serif;color:#3b2b2b;">'
            '<h2 style="color:#6E161E;">VenridesCafé</h2>'
            '<p>Hola %s:</p>'
            '<p>Tu código para firmar <strong>%s</strong> es:</p>'
            '<p style="font-size:30px;letter-spacing:6px;font-weight:bold;">%s</p>'
            '<p>Vence en 10 minutos.</p>'
            '</div>' % (self.employee_id.name or '', self.name or '', code))
        mail = self.env['mail.mail'].sudo().create({
            'subject': 'Código de firma — %s' % (self.name or ''),
            'email_to': self.signer_email,
            'email_from': self.company_id.email or '',
            'body_html': body,
        })
        try:
            mail.send()
        except Exception:  # noqa: BLE001
            pass
        return True

    def action_open_sign_page(self):
        self.ensure_one()
        return {'type': 'ir.actions.act_url', 'url': self.sign_url, 'target': 'new'}

    # ------------------------------------------------------------------
    # Firma
    # ------------------------------------------------------------------
    def _trim_image(self, data):
        image = Image.open(io.BytesIO(data)).convert('RGB')
        background = Image.new('RGB', image.size, (255, 255, 255))
        diff = ImageChops.difference(image, background)
        box = diff.getbbox()
        if box:
            margin = 8
            box = (
                max(box[0] - margin, 0), max(box[1] - margin, 0),
                min(box[2] + margin, image.width), min(box[3] + margin, image.height))
            image = image.crop(box)
        image.thumbnail((800, 400))
        output = io.BytesIO()
        image.save(output, format='PNG', optimize=True)
        return output.getvalue()

    def _dhash(self, data):
        image = Image.open(io.BytesIO(data)).convert('L').resize((9, 8))
        pixels = list(image.getdata())
        bits = []
        for row in range(8):
            for col in range(8):
                left = pixels[row * 9 + col]
                right = pixels[row * 9 + col + 1]
                bits.append(1 if left > right else 0)
        value = 0
        for bit in bits:
            value = (value << 1) | bit
        return '%016x' % value

    def _image_features(self, data):
        image = Image.open(io.BytesIO(data)).convert('L')
        background = Image.new('L', image.size, 255)
        box = ImageChops.difference(image, background).getbbox()
        if box:
            image = image.crop(box)
        width, height = image.size
        pixels = list(image.getdata())
        ink = sum(1 for value in pixels if value < 200)
        aspect = width / height if height else 0.0
        density = ink / (width * height) if width * height else 0.0
        return aspect, density

    def _hamming_similarity(self, hash_a, hash_b):
        if not hash_a or not hash_b:
            return 0.0
        distance = bin(int(hash_a, 16) ^ int(hash_b, 16)).count('1')
        return max(0.0, (1.0 - distance / 64.0) * 100.0)

    def _get_baseline_signature(self):
        self.ensure_one()
        if 'hr.contract' not in self.env:
            return self.env['venrides.sign.request']
        contract_model = self.env['hr.contract']
        if 'signature_image' not in contract_model._fields:
            return contract_model
        return contract_model.search([
            ('employee_id', '=', self.employee_id.id),
            ('signature_state', '=', 'signed'),
            ('signature_image', '!=', False),
        ], order='signed_date desc', limit=1)

    def _validate_strokes(self, strokes_json):
        try:
            strokes = json.loads(strokes_json or '[]')
        except (TypeError, ValueError):
            strokes = []
        points = []
        for stroke in strokes if isinstance(strokes, list) else []:
            for point in stroke if isinstance(stroke, list) else []:
                if isinstance(point, dict) and 't' in point:
                    points.append(point)
        count = len(points)
        duration = 0
        if points:
            times = [p.get('t', 0) for p in points]
            duration = int(max(times) - min(times))
        return count, duration, bool(strokes)

    def _content_hash(self, signature_hash):
        self.ensure_one()
        raw = '|'.join([
            str(self.id), self.reference or '', self.concept_name or '',
            '%.4f' % (self.amount_usd or 0.0), '%.4f' % (self.amount_bs or 0.0),
            str(self.payment_date or ''), str(self.employee_id.id or ''),
            signature_hash or '',
        ])
        return hashlib.sha256(raw.encode()).hexdigest()

    def _render_signed_pdf(self):
        self.ensure_one()
        if self.res_model and self.res_id and self.res_model in self.env:
            record = self.env[self.res_model].browse(self.res_id)
            if record.exists() and hasattr(record, '_render_signed_receipt'):
                return record._render_signed_receipt(self)
        pdf, _dummy = self.env['ir.actions.report'].sudo()._render_qweb_pdf(
            'venrides_hr_sign.report_signature_page', res_ids=self.ids)
        return pdf

    def _notify_hr(self, subject, body):
        self.ensure_one()
        email = (self.company_id.venrides_hr_alert_email
                 or self.company_id.email)
        if not email:
            return
        mail = self.env['mail.mail'].sudo().create({
            'subject': subject,
            'email_to': email,
            'email_from': self.company_id.email or 'no-reply@venrides.com',
            'body_html': body,
        })
        try:
            mail.send()
        except Exception:  # noqa: BLE001
            pass

    def action_decline(self, reason):
        self.ensure_one()
        if self.state == 'signed':
            raise UserError('Un documento ya firmado no se puede rechazar.')
        self.write({
            'state': 'declined',
            'notes': ((self.notes or '') + '\nRechazado: ' + (reason or '')).strip(),
        })
        self.message_post(body='Documento rechazado por %s. Motivo: %s' % (
            self.employee_id.name or '', reason or ''))
        self._notify_hr(
            'Documento rechazado — %s' % (self.reference or ''),
            '<p>El empleado <strong>%s</strong> rechazó el documento '
            '<strong>%s</strong>.</p><p>Motivo: %s</p>' % (
                self.employee_id.name or '', self.reference or '', reason or ''))
        return True

    def _send_signed_email(self):
        self.ensure_one()
        attachments = []
        if self.pdf_signed:
            attachments.append(self.env['ir.attachment'].create({
                'name': 'Recibo-firmado-%s.pdf' % (self.reference or self.id),
                'raw': self.pdf_signed.to_base64(),
                'res_model': 'venrides.sign.request',
                'res_id': self.id,
                'mimetype': 'application/pdf',
            }).id)
        if self.support:
            attachments.append(self.env['ir.attachment'].create({
                'name': self.support_filename or 'soporte-pago',
                'raw': self.support.to_base64(),
                'res_model': 'venrides.sign.request',
                'res_id': self.id,
            }).id)
        body = (
            '<div style="font-family:Arial,sans-serif;color:#3b2b2b;">'
            '<h2 style="color:#6E161E;">VenridesCafé</h2>'
            '<p>Hola %s:</p>'
            '<p>Adjuntamos el documento firmado <strong>%s</strong> y su soporte.</p>'
            '<p>Puedes descargarlo también desde: <a href="%s">%s</a></p>'
            '<p style="font-size:12px;color:#666;">Hash: %s</p>'
            '</div>' % (
                self.employee_id.name or '', self.reference or '',
                self.verify_url, self.verify_url, self.content_hash or ''))
        mail = self.env['mail.mail'].sudo().create({
            'subject': 'Documento firmado — %s' % (self.reference or ''),
            'email_to': self.signer_email,
            'email_from': self.company_id.email or '',
            'body_html': body,
            'attachment_ids': [(6, 0, attachments)],
        })
        try:
            mail.send()
        except Exception:  # noqa: BLE001
            pass

    def _validate_and_sign(self, image_b64, strokes_json, ip=None, user_agent=None):
        self.ensure_one()
        if self.state == 'signed':
            raise UserError('Este documento ya fue firmado.')
        if self.expiry_date and self.expiry_date < fields.Date.context_today(self):
            self.state = 'expired'
            raise UserError('El enlace de firma venció.')
        if not image_b64:
            raise UserError('No se recibió la firma.')
        try:
            raw = base64.b64decode(image_b64, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise UserError('La firma no es válida.') from exc

        point_count, duration, has_strokes = self._validate_strokes(strokes_json)
        if not has_strokes or point_count < 8 or duration < 400:
            raise UserError(
                'La firma debe realizarse en el recuadro con el dedo o el mouse. '
                'No se aceptan imágenes pegadas.')

        trimmed = self._trim_image(raw)
        image_hash = hashlib.sha256(trimmed).hexdigest()
        duplicate = self.search([
            ('id', '!=', self.id),
            ('signature_hash', '=', image_hash),
            ('state', '=', 'signed'),
        ], limit=1)
        if duplicate:
            raise UserError('Esta firma coincide exactamente con otra firma registrada.')

        image_dhash = self._dhash(trimmed)
        baseline = self._get_baseline_signature()
        similarity = 0.0
        check = 'no_baseline'
        if baseline and baseline.signature_image:
            baseline_raw = bytes(baseline.signature_image)
            try:
                baseline_trimmed = self._trim_image(baseline_raw)
                similarity = self._hamming_similarity(
                    image_dhash, self._dhash(baseline_trimmed))
                aspect_a, density_a = self._image_features(trimmed)
                aspect_b, density_b = self._image_features(baseline_trimmed)
                aspect_ok = (
                    abs(aspect_a - aspect_b) / max(aspect_a, aspect_b, 1.0)) < 0.35
                density_ok = (
                    abs(density_a - density_b) / max(density_a, density_b, 1e-6)) < 0.50
                threshold = self.company_id.venrides_signature_similarity_threshold or 90.0
                check = 'ok' if similarity >= threshold and aspect_ok and density_ok else 'review'
            except Exception:  # noqa: BLE001
                check = 'no_baseline'
        if baseline and baseline.signature_image and \
                hashlib.sha256(bytes(baseline.signature_image)).hexdigest() == image_hash:
            raise UserError('La firma es idéntica a la del contrato; no se acepta una copia.')

        content_hash = self._content_hash(image_hash)
        self.write({
            'state': 'signed',
            'signed_date': fields.Datetime.now(),
            'signature_image': base64.b64encode(trimmed).decode(),
            'signature_strokes': strokes_json,
            'signature_point_count': point_count,
            'signature_duration_ms': duration,
            'signature_hash': image_hash,
            'signature_dhash': image_dhash,
            'signature_similarity': similarity,
            'signature_check': check,
            'signature_ip': ip,
            'signature_user_agent': (user_agent or '')[:250],
            'content_hash': content_hash,
            'otp_hash': False,
            'otp_expiry': False,
        })
        self.env.flush_all()
        pdf = self._render_signed_pdf()
        self.write({
            'pdf_signed': base64.b64encode(pdf).decode(),
            'signed_pdf_hash': hashlib.sha256(pdf).hexdigest(),
        })
        self.message_post(body='Documento firmado por %s. Hash: %s. Validación: %s.' % (
            self.employee_id.name or '', content_hash, check))
        base = self.env['ir.config_parameter'].sudo().get_str('web.base.url', '')
        self._notify_hr(
            'Documento firmado — %s' % (self.reference or ''),
            '<p><strong>%s</strong> firmó <strong>%s</strong>.</p>'
            '<p>Validación: %s (similitud %.1f %%).</p>'
            '<p>Hash: %s</p>'
            '<p><a href="%s/web#id=%s&model=venrides.sign.request&view_type=form">'
            'Abrir en Odoo</a></p>' % (
                self.employee_id.name or '', self.reference or '', check,
                self.signature_similarity or 0.0, content_hash,
                base.rstrip('/'), self.id))
        self._send_signed_email()
        if self.res_model and self.res_id and self.res_model in self.env:
            record = self.env[self.res_model].browse(self.res_id)
            if record.exists() and hasattr(record, '_on_sign_request_signed'):
                record._on_sign_request_signed(self)
        return True

    @api.model
    def _cron_expire(self):
        today = fields.Date.context_today(self)
        self.search([
            ('state', 'in', ('sent', 'otp_sent')),
            ('expiry_date', '<', today),
        ]).write({'state': 'expired'})
