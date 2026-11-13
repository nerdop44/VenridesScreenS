# -*- coding: utf-8 -*-
from odoo import models, fields, api


class HrLeaveType(models.Model):
    _name = 'hr.leave.type'
    _description = 'Time Off Type'

    name = fields.Char(string='Name', required=True)
    requires_allocation = fields.Boolean(string='Requires Allocation', default=True)
    employee_requests = fields.Boolean(string='Allow Employee Requests', default=False)
    leave_validation_type = fields.Selection([
        ('both', 'Both'),
        ('user', 'User'),
        ('manager', 'Manager'),
    ], string='Leave Validation Type', default='both')
    allocation_validation_type = fields.Selection([
        ('hr', 'HR'),
        ('manager', 'Manager'),
        ('both', 'Both'),
    ], string='Allocation Validation Type', default='hr')
    leave_notif_subtype_id = fields.Many2one('mail.message.subtype', string='Time Off Notification Subtype', default=lambda self: self.env.ref('hr_holidays.mt_leave', raise_if_not_found=False))
    allocation_notif_subtype_id = fields.Many2one('mail.message.subtype', string='Allocation Notification Subtype', default=lambda self: self.env.ref('hr_holidays.mt_leave_allocation', raise_if_not_found=False))
    responsible_ids = fields.Many2many('res.users', string='Responsible')
    color = fields.Integer(string='Color')
    company_id = fields.Many2one('res.company', string='Company')
    sequence = fields.Integer(string='Sequence')
    work_entry_type_id = fields.Many2one('hr.work.entry.type', string='Work Entry Type')
