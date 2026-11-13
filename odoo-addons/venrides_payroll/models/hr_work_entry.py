from odoo import api, Command, fields, models, tools


class HrWorkEntryType(models.Model):
    _inherit = 'hr.work.entry.type'

    is_leave = fields.Boolean(string='Is Leave', default=False)
    round_days = fields.Selection([
        ('YES', 'Yes'),
        ('NO', 'No'),
    ], string='Round Days', default='NO')


class HrWorkEntry(models.Model):
    _name = 'hr.work.entry'
    _description = 'Work Entry'

    name = fields.Char(string='Descripción')
    employee_id = fields.Many2one('hr.employee', string='Empleado')
    department_id = fields.Many2one(
        'hr.department', string='Departamento',
        related='employee_id.department_id', store=True)
    date_start = fields.Datetime(string='Inicio')
    date_stop = fields.Datetime(string='Fin')
    work_entry_type_id = fields.Many2one('hr.work.entry.type', string='Tipo de Entrada')
    duration = fields.Float(string='Duración (horas)')
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('validated', 'Validado'),
        ('cancelled', 'Cancelado'),
    ], string='Estado', default='draft', required=True)
    company_id = fields.Many2one(
        'res.company', string='Compañía', default=lambda self: self.env.company)

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if vals.get('work_entry_type_id'):
                if vals['work_entry_type_id'] == self.env.ref('venrides_payroll.work_entry_type_VACA').id:
                    date_start = vals.get('date_start')
                    if date_start:
                        start_date = fields.Datetime.to_datetime(date_start).date()
                        if start_date.weekday() in (5, 6):
                            vals['work_entry_type_id'] = self.env.ref('venrides_payroll.work_entry_type_VACA_des_fer').id
        return super(HrWorkEntry, self).create(vals_list)

    def action_validate(self):
        self.write({'state': 'validated'})
        return True
