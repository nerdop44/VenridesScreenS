# -*- coding: utf-8 -*-
import base64
import hashlib

from odoo import fields, http
from odoo.exceptions import UserError
from odoo.http import request


OTP_MAX_ATTEMPTS = 5


class SignRequestController(http.Controller):

    def _get_request(self, token):
        return request.env['venrides.sign.request'].sudo().search(
            [('token', '=', token)], limit=1)

    def _render(self, sign_request, **kwargs):
        values = {
            'sign_request': sign_request,
            'employee': sign_request.employee_id,
            'company': sign_request.company_id,
            'error': False,
            'message': False,
            'otp_sent': False,
            'signed': False,
        }
        values.update(kwargs)
        return request.render('venrides_hr_sign.sign_portal', values)

    @http.route('/firma/<string:token>', type='http', auth='public', website=True)
    def sign_page(self, token, **kwargs):
        sign_request = self._get_request(token)
        if not sign_request:
            return request.not_found()
        if sign_request.state == 'signed':
            return self._render(sign_request, signed=True)
        return self._render(sign_request)

    @http.route('/firma/<string:token>/otp', type='http', auth='public',
                website=True, methods=['POST'], csrf=True)
    def send_otp(self, token, **kwargs):
        sign_request = self._get_request(token)
        if not sign_request:
            return request.not_found()
        if sign_request.state == 'signed':
            return self._render(sign_request, signed=True)
        if not sign_request.signer_email:
            sign_request.signer_email = (
                sign_request.employee_id.work_email
                or sign_request.employee_id.private_email)
        if not sign_request.signer_email:
            return self._render(
                sign_request, error='No hay un correo registrado para enviar el código.')
        sign_request.action_send_otp()
        return self._render(
            sign_request, otp_sent=True,
            message='Enviamos un código de 6 dígitos a %s. Vence en 10 minutos.'
                    % sign_request.signer_email)

    @http.route('/firma/<string:token>/confirmar', type='http', auth='public',
                website=True, methods=['POST'], csrf=True)
    def confirm(self, token, **kwargs):
        sign_request = self._get_request(token)
        if not sign_request:
            return request.not_found()
        if sign_request.state == 'signed':
            return self._render(sign_request, signed=True)

        code = (kwargs.get('otp_code') or '').strip()
        signature_data = kwargs.get('signature_data') or ''
        strokes = kwargs.get('signature_strokes') or '[]'
        if not sign_request.otp_hash:
            return self._render(sign_request, error='Primero solicita el código de verificación.')
        if sign_request.otp_expiry and sign_request.otp_expiry < fields.Datetime.now():
            return self._render(sign_request, error='El código venció. Solicita uno nuevo.')
        if sign_request.otp_attempts >= OTP_MAX_ATTEMPTS:
            return self._render(sign_request, error='Se agotaron los intentos. Solicita un nuevo código.')
        if hashlib.sha256(code.encode()).hexdigest() != sign_request.otp_hash:
            sign_request.write({'otp_attempts': sign_request.otp_attempts + 1})
            return self._render(sign_request, error='El código no es correcto.', otp_sent=True)
        if not signature_data.startswith('data:image/png;base64,'):
            return self._render(
                sign_request, error='Debes firmar en el recuadro antes de confirmar.',
                otp_sent=True)
        image_b64 = signature_data.split(',', 1)[1]
        try:
            base64.b64decode(image_b64, validate=True)
        except Exception:  # noqa: BLE001
            return self._render(sign_request, error='La firma no es válida.', otp_sent=True)
        try:
            sign_request._validate_and_sign(
                image_b64, strokes,
                ip=request.httprequest.remote_addr,
                user_agent=request.httprequest.user_agent.string or '')
        except UserError as exc:
            return self._render(sign_request, error=str(exc), otp_sent=True)
        return self._render(sign_request, signed=True)

    @http.route('/firma/<string:token>/rechazar', type='http', auth='public',
                website=True, methods=['POST'], csrf=True)
    def decline(self, token, **kwargs):
        sign_request = self._get_request(token)
        if not sign_request:
            return request.not_found()
        reason = (kwargs.get('reason') or '').strip()
        if not reason:
            return self._render(sign_request, error='Indica el motivo del rechazo.')
        try:
            sign_request.action_decline(reason)
        except UserError as exc:
            return self._render(sign_request, error=str(exc))
        return self._render(
            sign_request,
            error='Documento rechazado. RRHH fue notificado y revisará el caso.')

    @http.route('/firma/verificar/<string:token>', type='http', auth='public', website=True)
    def verify(self, token, **kwargs):
        sign_request = self._get_request(token)
        if not sign_request:
            return request.not_found()
        return request.render('venrides_hr_sign.sign_verify', {
            'sign_request': sign_request,
            'employee': sign_request.employee_id,
            'company': sign_request.company_id,
        })

    @http.route('/firma/descargar/<string:token>', type='http', auth='public')
    def download_signed(self, token, **kwargs):
        sign_request = self._get_request(token)
        if not sign_request or not sign_request.pdf_signed:
            return request.not_found()
        pdf = bytes(sign_request.pdf_signed)
        filename = 'Documento-firmado-%s.pdf' % (sign_request.reference or sign_request.id)
        return request.make_response(pdf, headers=[
            ('Content-Type', 'application/pdf'),
            ('Content-Disposition', 'attachment; filename="%s"' % filename),
            ('Content-Length', len(pdf)),
        ])

    @http.route('/firma/documento/<string:token>', type='http', auth='public')
    def download_unsigned(self, token, **kwargs):
        sign_request = self._get_request(token)
        if not sign_request or not sign_request.pdf_unsigned:
            return request.not_found()
        pdf = bytes(sign_request.pdf_unsigned)
        filename = 'Documento-%s.pdf' % (sign_request.reference or sign_request.id)
        return request.make_response(pdf, headers=[
            ('Content-Type', 'application/pdf'),
            ('Content-Disposition', 'inline; filename="%s"' % filename),
            ('Content-Length', len(pdf)),
        ])

    @http.route('/firma/soporte/<string:token>', type='http', auth='public')
    def download_support(self, token, **kwargs):
        sign_request = self._get_request(token)
        if not sign_request or not sign_request.support:
            return request.not_found()
        data = bytes(sign_request.support)
        filename = sign_request.support_filename or 'soporte'
        return request.make_response(data, headers=[
            ('Content-Type', 'application/octet-stream'),
            ('Content-Disposition', 'attachment; filename="%s"' % filename),
            ('Content-Length', len(data)),
        ])
