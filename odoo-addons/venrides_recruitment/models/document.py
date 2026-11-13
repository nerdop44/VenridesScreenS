# -*- coding: utf-8 -*-
from odoo import fields, models


DOC_TYPES = [
    ('cv', 'Currículum'),
    ('id_card', 'Cédula de identidad'),
    ('rif', 'RIF'),
    ('degree', 'Título / certificado'),
    ('medical', 'Certificado médico'),
    ('contract', 'Contrato'),
    ('annex', 'Anexo de contrato'),
    ('test', 'Resultado de test'),
    ('receipt', 'Recibo de pago'),
    ('payment_support', 'Soporte de abono'),
    ('photo', 'Foto del postulante'),
    ('other', 'Otro'),
]


class VenridesEmployeeDocument(models.Model):
    _name = 'venrides.employee.document'
    _description = 'Documento del expediente'
    _order = 'date desc, id desc'

    name = fields.Char(string='Nombre', required=True)
    doc_type = fields.Selection(DOC_TYPES, string='Tipo', required=True, default='other')
    applicant_id = fields.Many2one('hr.applicant', string='Postulante', ondelete='cascade')
    employee_id = fields.Many2one('hr.employee', string='Empleado', ondelete='cascade')
    attachment_id = fields.Many2one('ir.attachment', string='Archivo')
    date = fields.Date(string='Fecha', default=fields.Date.context_today)
    expiry_date = fields.Date(string='Vence')
    verified = fields.Boolean(string='Verificado')
    notes = fields.Text(string='Notas')
    company_id = fields.Many2one('res.company', default=lambda self: self.env.company)
