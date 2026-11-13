# -*- coding: utf-8 -*-
import base64
import io

from PIL import Image

from odoo import fields, models
from odoo.exceptions import UserError


class VenridesMedicalSupport(models.TransientModel):
    _name = 'venrides.medical.support'
    _description = 'Enviar reposo o justificativo médico'

    employee_id = fields.Many2one('hr.employee', string='Empleado', required=True)
    date = fields.Date(string='Fecha', default=fields.Date.context_today, required=True)
    description = fields.Char(string='Descripción', required=True,
                              placeholder='Reposo médico, justificativo de consulta...')
    attachment = fields.Binary(string='Documento', required=True)
    filename = fields.Char(string='Nombre del archivo')
    send_now = fields.Boolean(string='Enviar correo al empleado', default=True)

    def action_create_request(self):
        self.ensure_one()
        if not self.attachment:
            raise UserError('Adjunta el reposo o justificativo.')
        raw = base64.b64decode(self.attachment)
        filename = self.filename or 'reposo.pdf'
        pdf_bytes = raw
        if not filename.lower().endswith('.pdf'):
            try:
                image = Image.open(io.BytesIO(raw)).convert('RGB')
                output = io.BytesIO()
                image.save(output, format='PDF')
                pdf_bytes = output.getvalue()
                filename = filename.rsplit('.', 1)[0] + '.pdf'
            except Exception as exc:  # noqa: BLE001
                raise UserError('El archivo debe ser PDF o una imagen válida.') from exc
        request = self.env['venrides.sign.request'].create({
            'document_type': 'medical',
            'employee_id': self.employee_id.id,
            'signer_email': self.employee_id.work_email or self.employee_id.private_email,
            'reference': 'Reposo/Justificativo %s' % self.date,
            'concept_name': self.description,
            'payment_date': self.date,
            'pdf_unsigned': base64.b64encode(pdf_bytes).decode(),
            'support': self.attachment,
            'support_filename': filename,
            'res_model': 'hr.employee',
            'res_id': self.employee_id.id,
        })
        if self.send_now:
            request.action_send()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Documento para firma',
            'res_model': 'venrides.sign.request',
            'res_id': request.id,
            'view_mode': 'form',
            'target': 'current',
        }
