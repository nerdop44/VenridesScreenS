# -*- coding: utf-8 -*-
from datetime import timedelta

from odoo import api, fields, models
from odoo.exceptions import UserError

from ..models.contract import STAGE_DAYS


NEXT_STAGE = {
    'trial': '90',
    '90': '180',
    '180': '1y',
    '1y': 'indefinite',
    'indefinite': 'indefinite',
}


class VenridesContractRenewal(models.TransientModel):
    _name = 'venrides.contract.renewal'
    _description = 'Renovación de contrato'

    contract_id = fields.Many2one(
        'hr.contract', string='Contrato actual', required=True, readonly=True)
    employee_id = fields.Many2one(
        'hr.employee', string='Empleado', related='contract_id.employee_id')
    current_stage = fields.Selection(
        related='contract_id.contract_stage', string='Etapa actual')
    next_stage = fields.Selection([
        ('90', 'Inicial (90 días)'),
        ('180', 'Renovación (180 días)'),
        ('1y', 'Anual (1 año)'),
        ('indefinite', 'Indefinido / prórroga'),
    ], string='Nueva etapa', required=True, default='90')
    date_start = fields.Date(string='Inicio', required=True)
    date_end = fields.Date(string='Fin')
    template_id = fields.Many2one(
        'venrides.contract.template', string='Plantilla / versión')
    salary_table_id = fields.Many2one(
        'venrides.salary.table', string='Tabla salarial')
    copy_annexes = fields.Boolean(string='Copiar anexos', default=True)
    notes = fields.Text(string='Notas de la renovación')

    @api.model
    def default_get(self, fields_list):
        result = super().default_get(fields_list)
        contract = self.env['hr.contract'].browse(
            self.env.context.get('default_contract_id') or
            self.env.context.get('active_id'))
        if contract:
            result.setdefault('contract_id', contract.id)
            result.setdefault('next_stage', NEXT_STAGE.get(contract.contract_stage, 'indefinite'))
            start = (contract.date_end + timedelta(days=1)) if contract.date_end else fields.Date.context_today(self)
            result.setdefault('date_start', start)
            result.setdefault('template_id', contract.template_id.id)
            result.setdefault('salary_table_id', contract.salary_table_id.id)
            days = STAGE_DAYS.get(result.get('next_stage'), 0)
            result.setdefault('date_end', start + timedelta(days=days - 1) if days else False)
        return result

    @api.onchange('next_stage', 'date_start')
    def _onchange_stage(self):
        if self.date_start:
            days = STAGE_DAYS.get(self.next_stage, 0)
            self.date_end = self.date_start + timedelta(days=days - 1) if days else False

    def action_create(self):
        self.ensure_one()
        contract = self.contract_id
        if not self.date_start:
            raise UserError('Indica la fecha de inicio del nuevo contrato.')
        if self.date_end and self.date_end < self.date_start:
            raise UserError('La fecha de fin no puede ser anterior al inicio.')

        overlap = self.env['hr.contract'].search([
            ('employee_id', '=', contract.employee_id.id),
            ('id', '!=', contract.id),
            ('state', 'in', ('open', 'pending')),
            ('date_start', '<=', self.date_end or fields.Date.today() + timedelta(days=3650)),
            '|', ('date_end', '=', False), ('date_end', '>=', self.date_start),
        ], limit=1)
        if overlap:
            raise UserError(
                'El empleado ya tiene un contrato vigente que se solapa: %s (%s a %s).'
                % (overlap.contract_number or overlap.id,
                   overlap.date_start, overlap.date_end or 'indefinido'))

        new_contract = self.env['hr.contract'].create({
            'employee_id': contract.employee_id.id,
            'company_id': contract.company_id.id,
            'contract_type_id': contract.contract_type_id.id,
            'structure_type_id': contract.structure_type_id.id,
            'schedule_pay': contract.schedule_pay,
            'date_start': self.date_start,
            'date_end': self.date_end,
            'state': 'open',
            'resource_calendar_id': contract.resource_calendar_id.id,
            'standard_calendar_id': contract.standard_calendar_id.id,
            'currency_id': contract.currency_id.id,
            'currency_id_dif': contract.currency_id_dif.id,
            'wage': contract.wage,
            'wage_usd': contract.wage_usd,
            'complemento': contract.complemento,
            'HED': contract.HED,
            'HEN': contract.HEN,
            'HED_usd': contract.HED_usd,
            'HEN_usd': contract.HEN_usd,
            'retencion_islr': contract.retencion_islr,
            'retencion_faov': contract.retencion_faov,
            'retencion_sso': contract.retencion_sso,
            'retencion_rpe': contract.retencion_rpe,
            'dias_utilidades': contract.dias_utilidades,
            'dias_bono_vacacional': contract.dias_bono_vacacional,
            'job_id': contract.job_id.id,
            'contract_stage': self.next_stage,
            'parent_contract_id': contract.id,
            'template_id': self.template_id.id or contract.template_id.id,
            'salary_table_id': self.salary_table_id.id or contract.salary_table_id.id,
            'salary_table_line_id': contract.salary_table_line_id.id,
            'bono_guerra_usd': contract.bono_guerra_usd,
            'bono_transporte_usd': contract.bono_transporte_usd,
            'bono_desempeno_max_usd': contract.bono_desempeno_max_usd,
            'cestaticket_usd': contract.cestaticket_usd,
            'schedule_description': contract.schedule_description,
            'signer_email': contract.signer_email,
            'annex_ids': [(6, 0, contract.annex_ids.ids)] if self.copy_annexes else [(5, 0, 0)],
            'signature_state': 'draft',
        })
        return {
            'type': 'ir.actions.act_window',
            'name': 'Contrato renovado',
            'res_model': 'hr.contract',
            'res_id': new_contract.id,
            'view_mode': 'form',
            'target': 'current',
        }
