# -*- coding: utf-8 -*-
from odoo import fields, models


class HrEmployee(models.Model):
    _inherit = 'hr.employee'

    sign_request_ids = fields.One2many(
        'venrides.sign.request', 'employee_id', string='Documentos para firma')

    def action_create_medical_support(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Enviar reposo / justificativo',
            'res_model': 'venrides.medical.support',
            'view_mode': 'form',
            'target': 'new',
            'context': {'default_employee_id': self.id},
        }

    def action_view_sign_requests(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Documentos para firma',
            'res_model': 'venrides.sign.request',
            'view_mode': 'list,form',
            'domain': [('employee_id', '=', self.id)],
            'context': {'default_employee_id': self.id},
        }
