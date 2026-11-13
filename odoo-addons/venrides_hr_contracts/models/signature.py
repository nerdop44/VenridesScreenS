# -*- coding: utf-8 -*-
from odoo import fields, models


class VenridesContractSignature(models.Model):
    _name = 'venrides.contract.signature'
    _description = 'Evidencia de firma de contrato'
    _order = 'id desc'

    contract_id = fields.Many2one(
        'hr.contract', string='Contrato', required=True, ondelete='cascade')
    signer_name = fields.Char(string='Firmante')
    signer_email = fields.Char(string='Correo')
    method = fields.Selection([
        ('canvas', 'Firma digital en pantalla'),
        ('physical', 'Firma física escaneada'),
        ('external', 'Firma electrónica externa'),
    ], string='Método')
    state = fields.Selection([
        ('sent', 'Enviado'),
        ('signed', 'Firmado'),
        ('declined', 'Rechazado'),
        ('expired', 'Vencido'),
    ], string='Estado', default='sent')
    sent_at = fields.Datetime(string='Enviado', default=fields.Datetime.now)
    verified_at = fields.Datetime(string='Verificado')
    ip_address = fields.Char(string='IP')
    user_agent = fields.Char(string='Navegador')
    image = fields.Binary(string='Imagen de firma', attachment=True)
    document_hash = fields.Char(string='Hash SHA-256 del documento')
    notes = fields.Text(string='Notas')
