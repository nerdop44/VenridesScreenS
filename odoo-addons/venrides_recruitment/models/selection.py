# -*- coding: utf-8 -*-
from odoo import fields, models


PHASE_TYPES = [
    ('test', 'Test de conocimientos'),
    ('interview', 'Entrevista'),
    ('training', 'Capacitación'),
    ('physical', 'Pruebas físicas'),
    ('contract', 'Contratación'),
]

PHASE_RESULTS = [
    ('pending', 'Pendiente'),
    ('passed', 'Aprobado'),
    ('failed', 'No aprobado'),
    ('no_show', 'No asistió'),
]


class VenridesSelectionPhase(models.Model):
    _name = 'venrides.selection.phase'
    _description = 'Fase de selección'
    _inherit = ['mail.thread']
    _order = 'date desc, id desc'

    name = fields.Char(string='Fase', compute='_compute_name', store=True)
    applicant_id = fields.Many2one(
        'hr.applicant', string='Postulante', required=True, ondelete='cascade')
    phase_type = fields.Selection(PHASE_TYPES, string='Tipo', required=True)
    date = fields.Date(string='Fecha', default=fields.Date.context_today)
    evaluator_id = fields.Many2one('res.users', string='Evaluador')
    result = fields.Selection(PHASE_RESULTS, string='Resultado', default='pending')
    score = fields.Float(string='Puntaje')
    notes = fields.Text(string='Observaciones')
    attachment_ids = fields.Many2many(
        'ir.attachment', 'venrides_phase_attachment_rel', 'phase_id', 'attachment_id',
        string='Evidencias')
    company_id = fields.Many2one('res.company', default=lambda self: self.env.company)

    def _compute_name(self):
        labels = dict(PHASE_TYPES)
        for phase in self:
            phase.name = labels.get(phase.phase_type, 'Fase')
