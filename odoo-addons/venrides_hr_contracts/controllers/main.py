# -*- coding: utf-8 -*-
import base64
import hashlib
import secrets
from datetime import timedelta

from markupsafe import Markup

from odoo import fields, http
from odoo.http import request


OTP_MAX_ATTEMPTS = 5
OTP_VALID_MINUTES = 10


class ContractSignatureController(http.Controller):

    def _get_contract(self, token):
        return request.env['hr.contract'].sudo().search(
            [('signature_token', '=', token)], limit=1)

    def _render(self, contract, **kwargs):
        values = {
            'contract': contract,
            'employee': contract.employee_id,
            'company': contract.company_id,
            'error': False,
            'message': False,
            'otp_sent': False,
            'signed': False,
        }
        values.update(kwargs)
        return request.render('venrides_hr_contracts.contract_sign', values)

    @http.route('/contrato/firmar/<string:token>', type='http', auth='public', website=True)
    def sign_page(self, token, **kwargs):
        contract = self._get_contract(token)
        if not contract:
            return request.not_found()
        if contract.signature_state == 'signed':
            return self._render(contract, signed=True)
        return self._render(contract)

    @http.route('/contrato/firmar/<string:token>/otp', type='http', auth='public',
                website=True, methods=['POST'], csrf=True)
    def send_otp(self, token, **kwargs):
        contract = self._get_contract(token)
        if not contract:
            return request.not_found()
        if contract.signature_state == 'signed':
            return self._render(contract, signed=True)

        email = contract.signer_email or contract.employee_id.work_email \
            or contract.employee_id.private_email
        if not email:
            return self._render(
                contract, error='No hay un correo registrado para enviar el código. '
                                'Contacta a Recursos Humanos.')

        code = '%06d' % secrets.randbelow(1000000)
        contract.write({
            'signer_email': email,
            'signature_otp_hash': hashlib.sha256(code.encode()).hexdigest(),
            'signature_otp_expiry': fields.Datetime.now() + timedelta(minutes=OTP_VALID_MINUTES),
            'signature_otp_attempts': 0,
            'signature_state': 'otp_sent',
        })

        body = Markup(
            '<div style="font-family:Arial,sans-serif;color:#3b2b2b;">'
            '<h2 style="color:#6E161E;">VenridesCafé</h2>'
            '<p>Hola %s:</p>'
            '<p>Tu código para firmar el contrato <strong>%s</strong> es:</p>'
            '<p style="font-size:30px;letter-spacing:6px;font-weight:bold;">%s</p>'
            '<p>El código vence en %s minutos. Si no solicitaste este código, '
            'ignora este mensaje.</p>'
            '</div>') % (
                contract.employee_id.name or '', contract.contract_number or '', code,
                OTP_VALID_MINUTES)

        mail = request.env['mail.mail'].sudo().create({
            'subject': 'Código de firma — Contrato %s' % (contract.contract_number or ''),
            'email_to': email,
            'email_from': contract.company_id.email or '',
            'body_html': body,
            'model': 'hr.contract',
            'res_id': contract.id,
        })
        try:
            mail.send()
        except Exception:  # noqa: BLE001
            # Si el servidor de correo falla, el código queda registrado y se
            # puede reenviar. No exponemos el código en la página.
            pass

        return self._render(
            contract, otp_sent=True,
            message='Enviamos un código de 6 dígitos a %s. Vence en %s minutos.'
                    % (email, OTP_VALID_MINUTES))

    @http.route('/contrato/firmar/<string:token>/confirmar', type='http', auth='public',
                website=True, methods=['POST'], csrf=True)
    def confirm_signature(self, token, **kwargs):
        contract = self._get_contract(token)
        if not contract:
            return request.not_found()
        if contract.signature_state == 'signed':
            return self._render(contract, signed=True)

        code = (kwargs.get('otp_code') or '').strip()
        signature_data = kwargs.get('signature_data') or ''
        if not contract.signature_otp_hash:
            return self._render(
                contract, error='Primero solicita el código de verificación.')
        if contract.signature_otp_expiry and contract.signature_otp_expiry < fields.Datetime.now():
            return self._render(
                contract, error='El código venció. Solicita uno nuevo.')
        if contract.signature_otp_attempts >= OTP_MAX_ATTEMPTS:
            return self._render(
                contract, error='Se agotaron los intentos. Solicita un nuevo código.')
        if hashlib.sha256(code.encode()).hexdigest() != contract.signature_otp_hash:
            contract.write({'signature_otp_attempts': contract.signature_otp_attempts + 1})
            return self._render(contract, error='El código no es correcto.', otp_sent=True)
        if not signature_data.startswith('data:image/png;base64,'):
            return self._render(
                contract, error='Debes firmar en el recuadro antes de confirmar.',
                otp_sent=True)

        image_b64 = signature_data.split(',', 1)[1]
        try:
            base64.b64decode(image_b64, validate=True)
        except Exception:  # noqa: BLE001
            return self._render(contract, error='La firma no es válida.', otp_sent=True)

        contract._sign_with_canvas(
            image_b64,
            ip=request.httprequest.remote_addr,
            user_agent=request.httprequest.user_agent.string or '',
        )
        return self._render(contract, signed=True)

    @http.route('/contrato/descargar/<string:token>', type='http', auth='public')
    def download_signed(self, token, **kwargs):
        contract = self._get_contract(token)
        if not contract or not contract.signed_pdf:
            return request.not_found()
        pdf = bytes(contract.signed_pdf)
        filename = 'Contrato-%s.pdf' % (contract.contract_number or contract.id)
        return request.make_response(pdf, headers=[
            ('Content-Type', 'application/pdf'),
            ('Content-Disposition', 'attachment; filename="%s"' % filename),
            ('Content-Length', len(pdf)),
        ])
