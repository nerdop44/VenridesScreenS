# -*- coding: utf-8 -*-
from odoo import fields, models


class ResCompany(models.Model):
    _inherit = 'res.company'

    venrides_signature_similarity_threshold = fields.Float(
        string='Umbral de similitud de firma (%)', default=90.0,
        help='Si la firma del recibo se parece menos que este porcentaje a la '
             'firma del contrato, queda marcada para revisión.')
    venrides_hr_alert_email = fields.Char(
        string='Correo de alertas de RRHH', default='info@venrides.com',
        help='Recibe avisos cuando un documento se firma, queda en revisión o se rechaza.')
    venrides_signature_require_strokes = fields.Boolean(
        string='Exigir trazos de firma', default=True,
        help='Rechaza imágenes pegadas: la firma debe dibujarse en pantalla.')
