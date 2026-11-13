# -*- coding: utf-8 -*-
from datetime import timedelta

import pandas as pd

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError


class HrLeave(models.Model):
    _inherit = 'hr.leave'

    dias_habiles = fields.Integer(string="Días Hábiles", compute="_compute_dias_habiles", store=True)
    dias_fer_desc = fields.Integer(string="Días Feriados y Descanso", compute="_compute_dias_fer_desc", store=True)
    vaca_disponible = fields.Integer(string="Días Disponibles", compute="_compute_disponibles", store=True)
    dias_a_disfrutar = fields.Integer(string="Días a Disfrutar")
    is_vaca = fields.Boolean(string="Es Vacaciones", compute="_compute_is_vaca", store=True)

    def _get_vacation_type(self):
        return self.env.ref('venrides_payroll.work_entry_type_VACA', raise_if_not_found=False)

    @api.depends('work_entry_type_id')
    def _compute_is_vaca(self):
        vaca_type = self._get_vacation_type()
        for rec in self:
            rec.is_vaca = bool(vaca_type) and rec.work_entry_type_id == vaca_type

    @api.onchange('dias_a_disfrutar')
    def _onchange_dias_a_disfrutar(self):
        for rec in self:
            if not rec.is_vaca or not rec.employee_id:
                continue
            if rec.dias_a_disfrutar > rec.vaca_disponible:
                raise ValidationError(_("No puede solicitar más días de los disponibles"))
            fecha_hasta = rec.request_date_from - timedelta(days=1)
            restantes = rec.dias_a_disfrutar
            while restantes > 0:
                fecha_hasta += timedelta(days=1)
                if fecha_hasta.weekday() not in (5, 6):
                    restantes -= 1
            rec.request_date_to = fecha_hasta

    @api.depends('employee_id')
    def _compute_disponibles(self):
        for rec in self:
            if rec.employee_id and rec.employee_id.contract_id:
                rec.vaca_disponible = rec.employee_id.contract_id.vaca_disponible
            else:
                rec.vaca_disponible = 0

    @api.depends('request_date_from', 'request_date_to')
    def _compute_dias_fer_desc(self):
        for rec in self:
            dfd = 0
            if rec.request_date_from and rec.request_date_to:
                current = rec.request_date_from
                while current <= rec.request_date_to:
                    if current.weekday() in (5, 6):
                        dfd += 1
                    current += timedelta(days=1)
            rec.dias_fer_desc = dfd

    @api.depends('request_date_from', 'request_date_to')
    def _compute_dias_habiles(self):
        for rec in self:
            dh = 0
            if rec.request_date_from and rec.request_date_to:
                for day in pd.date_range(start=rec.request_date_from, end=rec.request_date_to):
                    if day.weekday() not in (5, 6):
                        dh += 1
            rec.dias_habiles = dh
