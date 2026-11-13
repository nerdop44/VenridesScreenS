
from odoo import models, fields, api


class HRPayslipRun(models.Model):
    _name = 'hr.payslip.run'
    _description = 'Lote de Nómina'
    _order = 'date_start desc, id desc'

    name = fields.Char(string='Nombre del Lote', required=True,
                       default=lambda self: self.env._('Nuevo Lote'))
    date_start = fields.Date(string='Fecha Desde')
    date_end = fields.Date(string='Fecha Hasta')
    state = fields.Selection([
        ('draft', 'Borrador'),
        ('close', 'Cerrado'),
    ], string='Estado', default='draft', required=True, copy=False, index=True)
    company_id = fields.Many2one('res.company', string='Compañía',
                                 default=lambda self: self.env.company)
    slip_ids = fields.One2many('hr.payslip', 'payslip_run_id', string='Recibos de Nómina')
    tasa_cambio = fields.Float(store=True, string="Tasa de Cambio",
                               default=lambda self: self._get_default_tasa_cambio())

    def _get_default_tasa_cambio(self):
        dolar = self.env['res.currency'].search([('name', '=', 'USD')], limit=1)
        tasa = 1 / dolar.rate if dolar and dolar.rate else 1.0
        return tasa

    def write(self, vals):
        res = super(HRPayslipRun, self).write(vals)
        if 'tasa_cambio' in vals:
            for rec in self:
                for slip in rec.slip_ids:
                    slip.tasa_cambio = vals['tasa_cambio']
                    slip.compute_sheet()
        if 'date_start' in vals or 'date_end' in vals:
            for rec in self:
                for slip in rec.slip_ids:
                    if 'date_start' in vals:
                        slip.date_from = vals['date_start']
                    if 'date_end' in vals:
                        slip.date_to = vals['date_end']
                    slip.compute_sheet()
        return res

    def action_close(self):
        self.write({'state': 'close'})
        return True

    def action_draft(self):
        self.write({'state': 'draft'})
        return True

    def action_open_report(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.client',
            'name': 'Listado Nóminas por Empleados',
            'tag': 'account_report',
            'context': {
                'report_id': self.env.ref('venrides_payroll.venrides_payroll_report_nomina_empleados').id,
                'date_from': self.date_start,
                'date_to': self.date_end,
                'slip_ids': self.slip_ids.ids,
                'company_id': self.company_id.id,
                'previous_options': True,
            }
        }
