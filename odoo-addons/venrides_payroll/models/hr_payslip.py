# -*- coding: utf-8 -*-
from odoo import api, Command, fields, models, _
from odoo.exceptions import UserError, ValidationError
from odoo.tools import float_round, html2plaintext, is_html_empty, format_amount
from odoo.tools.float_utils import float_compare
from odoo.tools.misc import format_date
from odoo.tools.safe_eval import safe_eval

import base64
import calendar
import logging
import math
import random
from collections import defaultdict, Counter
from datetime import date, datetime, timedelta
from dateutil.relativedelta import relativedelta

_logger = logging.getLogger(__name__)


class _AttrDict(dict):
    """Diccionario que permite acceso por atributo dentro de safe_eval."""

    def __init__(self, *args, default=False, **kwargs):
        super().__init__(*args, **kwargs)
        self._default = default

    def __getattr__(self, key):
        if key.startswith('__'):
            raise AttributeError(key)
        return self.get(key, self._default)


class HRPayslip(models.Model):
    _name = 'hr.payslip'
    _inherit = ['mail.thread', 'mail.activity.mixin']
    _description = 'Pay Slip'
    _order = 'date_to desc'

    struct_id = fields.Many2one('hr.payroll.structure', string='Structure', required=True, store=True)
    name = fields.Char(string='Payslip Name', required=True, store=True, readonly=False, compute='_compute_name', precompute=True)
    number = fields.Char(string='Reference', copy=False)
    employee_id = fields.Many2one('hr.employee', string='Employee', required=True)
    contract_id = fields.Many2one('hr.contract', string='Contract')
    department_id = fields.Many2one('hr.department', related='employee_id.department_id', readonly=True)
    job_id = fields.Many2one('hr.job', related='employee_id.job_id', readonly=True)
    date_from = fields.Date(string='From', required=True, store=True, readonly=False, compute='_compute_date_from', precompute=True)
    date_to = fields.Date(string='To', required=True, store=True, readonly=False, compute='_compute_date_to', precompute=True)
    state = fields.Selection([
        ('draft', 'Draft'),
        ('verify', 'Waiting'),
        ('done', 'Done'),
        ('paid', 'Paid'),
        ('cancel', 'Canceled'),
    ], string='Status', index=True, readonly=True, copy=False, default='draft')
    line_ids = fields.One2many('hr.payslip.line', 'slip_id', string='Payslip Lines', compute='_compute_line_ids', store=True, readonly=False, copy=True)
    company_id = fields.Many2one('res.company', string='Company', required=True, compute='_compute_company_id', store=True, readonly=True, precompute=True, default=lambda self: self.env.company)
    currency_id = fields.Many2one('res.currency', related='contract_id.currency_id')
    currency_id_dif = fields.Many2one("res.currency", string="Referencia en Divisa",
                                      default=lambda self: self.env['res.currency'].search([('name', '=', 'USD')], limit=1))
    worked_days_line_ids = fields.One2many('hr.payslip.worked_days', 'payslip_id', string='Payslip Worked Days', compute='_compute_worked_days_line_ids', store=True, readonly=False)
    input_line_ids = fields.One2many('hr.payslip.input', 'payslip_id', string='Payslip Inputs', compute='_compute_input_line_ids', store=True, readonly=False)
    payslip_run_id = fields.Many2one('hr.payslip.run', string='Batch Name', ondelete='cascade')
    sum_worked_hours = fields.Float(compute='_compute_worked_hours', store=True)
    compute_date = fields.Date('Computed On')
    basic_wage = fields.Monetary(compute='_compute_basic_net', store=True)
    gross_wage = fields.Monetary(compute='_compute_basic_net', store=True)
    net_wage = fields.Monetary(compute='_compute_basic_net', store=True)
    net_wage_usd = fields.Monetary(store=True, string="Total (USD)", currency_field='currency_id_dif', compute='_compute_basic_net')
    tasa_cambio = fields.Float(string="Tasa de Cambio", default=1 / 1, store=True, digits=(16, 4))
    basic_wage = fields.Monetary(compute='_compute_basic_net', store=True)
    wage = fields.Monetary(store=True, related='contract_id.wage', string="Salario Mensual (Bs)")
    wage_usd = fields.Monetary(store=True, readonly=True, related='contract_id.wage_usd', string="Salario Mensual (USD)")
    wage_diario = fields.Float(store=True, readonly=True, compute="_wage_diario", string="Sueldo Diario (Bs)")
    wage_diario_usd = fields.Float(store=True, readonly=True, compute="_wage_diario_usd", string="Salario Diario (USD)")
    complemento = fields.Monetary(store=True, related='contract_id.complemento')
    complemento_mensual = fields.Float(store=True, related='contract_id.complemento_mensual')
    complemento_mensual_bs = fields.Float(store=True, readonly=True, compute='_complemento_mensual_bs')
    complemento_diario = fields.Float(store=True, readonly=True, compute='_complemento_diario')
    complemento_diario_bs = fields.Float(store=True, readonly=True, compute='_complemeto_diario_bs')
    lunes_mes = fields.Integer(store=True, compute='_calcular_lunes', string="Lunes del mes")
    lunes_periodo = fields.Integer(store=True, compute='_calcular_lunes', string="Lunes del periodo")
    adelanto = fields.Float(string="Adelanto quincenal", store=True, readonly=False, compute="_adelanto")
    pestaciones_id = fields.Many2one('hr.employee.prestaciones', string="Prestaciones Sociales")
    installment_ids = fields.Many2many('hr.employee.loan.installment.line', string='Cuotas de Préstamos')
    installment_amount = fields.Float('Monto de Cuotas', compute='get_installment_amount')
    installment_int = fields.Float('Monto Intereses', compute='get_installment_amount')
    sign_request_id = fields.Many2one('sign.request', string='Solicitud de Firma')
    pdf_signed = fields.Boolean(string='PDF Firmado', copy=False, default=False)
    resultado_incentivo_manual = fields.Boolean(default=True)
    adelanto_manual = fields.Boolean(default=True)
    move_id = fields.Many2one('account.move', string='Account Move')
    warning_message = fields.Char(compute='_compute_warning_message', store=True, readonly=True)
    is_wrong_duration = fields.Boolean(compute='_compute_is_wrong_duration', compute_sudo=True)
    is_regular = fields.Boolean(compute='_compute_is_regular')
    has_refund_slip = fields.Boolean(compute='_compute_has_refund_slip')
    negative_net_to_report = fields.Boolean()
    negative_net_to_report_display = fields.Boolean(compute='_compute_negative_net_to_report_display')
    negative_net_to_report_message = fields.Char(compute='_compute_negative_net_to_report_display')
    negative_net_to_report_amount = fields.Float(compute='_compute_negative_net_to_report_display')
    is_superuser = fields.Boolean(compute="_compute_is_superuser")
    edited = fields.Boolean()
    queued_for_pdf = fields.Boolean(default=False)
    salary_attachment_ids = fields.Many2many('hr.salary.attachment', relation='hr_payslip_hr_salary_attachment_rel', string='Salary Attachments', compute='_compute_salary_attachment_ids', store=True, readonly=False)
    salary_attachment_count = fields.Integer('Salary Attachment count', compute='_compute_salary_attachment_count')
    use_worked_day_lines = fields.Boolean(related="struct_id.use_worked_day_lines")
    payment_report = fields.Binary(string='Payment Report', readonly=True)
    payment_report_filename = fields.Char(readonly=True)
    payment_report_date = fields.Date(readonly=True)
    ytd_computation = fields.Boolean(related='struct_id.ytd_computation')
    credit_note = fields.Boolean(string='Nota de Crédito', readonly=True, copy=False)
    paid_date = fields.Date(string='Fecha de Pago', copy=False)
    has_negative_net_to_report = fields.Boolean(string='Neto Negativo por Reportar', copy=False)

    # ------------------------------------------------------- campos calculados
    @api.depends('employee_id', 'contract_id')
    def _compute_company_id(self):
        for payslip in self:
            payslip.company_id = (
                payslip.contract_id.company_id
                or payslip.employee_id.company_id
                or self.env.company
            )

    @api.depends('contract_id.wage', 'contract_id.wage_usd', 'tasa_cambio',
                 'contract_id.complemento_mensual')
    def _calcular_lunes(self):
        for payslip in self:
            payslip.lunes_mes = 0
            payslip.lunes_periodo = 0
            if not (payslip.date_from and payslip.date_to):
                continue
            # lunes del mes de la fecha desde
            first_day = payslip.date_from.replace(day=1)
            last_day = first_day + relativedelta(months=1, days=-1)
            current = first_day
            while current <= last_day:
                if current.weekday() == 0:
                    payslip.lunes_mes += 1
                current += timedelta(days=1)
            # lunes dentro del periodo de la nómina
            current = payslip.date_from
            while current <= payslip.date_to:
                if current.weekday() == 0:
                    payslip.lunes_periodo += 1
                current += timedelta(days=1)

    @api.depends('wage')
    def _wage_diario(self):
        for payslip in self:
            payslip.wage_diario = (payslip.wage or 0.0) / 30.0

    @api.depends('wage_usd')
    def _wage_diario_usd(self):
        for payslip in self:
            payslip.wage_diario_usd = (payslip.wage_usd or 0.0) / 30.0

    @api.depends('complemento_mensual', 'tasa_cambio')
    def _complemento_mensual_bs(self):
        for payslip in self:
            payslip.complemento_mensual_bs = (payslip.complemento_mensual or 0.0) * (payslip.tasa_cambio or 0.0)

    @api.depends('complemento_mensual')
    def _complemento_diario(self):
        for payslip in self:
            payslip.complemento_diario = (payslip.complemento_mensual or 0.0) / 30.0

    @api.depends('complemento_diario', 'tasa_cambio')
    def _complemeto_diario_bs(self):
        for payslip in self:
            payslip.complemento_diario_bs = (payslip.complemento_diario or 0.0) * (payslip.tasa_cambio or 0.0)

    @api.depends('contract_id.wage', 'contract_id', 'adelanto_manual')
    def _adelanto(self):
        for payslip in self:
            if not payslip.adelanto_manual and payslip.contract_id:
                payslip.adelanto = (payslip.contract_id.wage or 0.0) / 2.0
            else:
                payslip.adelanto = 0.0

    @api.depends('employee_id', 'contract_id', 'struct_id', 'date_from', 'date_to')
    def _compute_worked_days_line_ids(self):
        for payslip in self:
            if not payslip.struct_id or not payslip.struct_id.use_worked_day_lines or not payslip.contract_id:
                payslip.worked_days_line_ids = [Command.clear()]
                continue
            try:
                lines = payslip._get_worked_day_lines()
            except Exception:  # noqa: BLE001 - una nómina no debe romperse por el calendario
                lines = []
            payslip.worked_days_line_ids = [Command.clear()] + [
                Command.create(line) for line in lines
            ]

    @api.depends('date_from', 'date_to', 'contract_id', 'struct_id')
    def _compute_is_wrong_duration(self):
        for payslip in self:
            payslip.is_wrong_duration = False
            if payslip.date_from and payslip.date_to and payslip.contract_id:
                expected_to = payslip.date_from + payslip._get_schedule_timedelta()
                payslip.is_wrong_duration = payslip.date_to != expected_to

    @api.depends('is_wrong_duration')
    def _compute_warning_message(self):
        for payslip in self:
            payslip.warning_message = (
                _('La duración de la nómina no coincide con la del contrato.')
                if payslip.is_wrong_duration else False
            )

    @api.depends('employee_id', 'struct_id', 'date_from', 'date_to')
    def _compute_salary_attachment_ids(self):
        for payslip in self:
            payslip.salary_attachment_ids = payslip.employee_id.salary_attachment_ids

    def _get_line_values(self, codes, compute_sum=False):
        """Devuelve totales por código de regla o por código de categoría."""
        result = {}
        for code in codes:
            per_payslip = {}
            total = 0.0
            for payslip in self:
                amount = sum(
                    payslip.line_ids.filtered(
                        lambda l, c=code: l.code == c or l.category_id.code == c
                    ).mapped('total')
                )
                per_payslip[payslip.id] = {'total': amount}
                total += amount
            if compute_sum:
                result[code] = {'sum': {'total': total}}
            else:
                result[code] = per_payslip
        return result

    # ------------------------------------------------------------------ utils
    @api.depends('employee_id', 'date_from', 'date_to')
    def _compute_name(self):
        for payslip in self:
            if not payslip.name:
                employee = payslip.employee_id.name or ''
                period = payslip.date_from or ''
                payslip.name = ('%s - %s' % (employee, period)).strip(' -')

    @api.depends('installment_ids', 'installment_ids.installment_amt',
                 'installment_ids.ins_interest', 'installment_ids.is_paid')
    def get_installment_amount(self):
        for payslip in self:
            lines = payslip.installment_ids.filtered(lambda l: not l.is_paid)
            payslip.installment_amount = sum(lines.mapped('installment_amt'))
            payslip.installment_int = sum(lines.mapped('ins_interest'))

    def _get_schedule_period_start(self):
        schedule = self.contract_id.schedule_pay or self.contract_id.structure_type_id.default_schedule_pay
        today = date.today()
        week_start = self.env["res.lang"]._get_data(code=self.env.user.lang).week_start
        date_from = today
        if schedule == 'quarterly':
            current_year_quarter = math.ceil(today.month / 3)
            date_from = today.replace(day=1, month=(current_year_quarter - 1) * 3 + 1)
        elif schedule == 'semi-annually':
            is_second_half = math.floor((today.month - 1) / 6)
            date_from = today.replace(day=1, month=7) if is_second_half else today.replace(day=1, month=1)
        elif schedule == 'annually':
            date_from = today.replace(day=1, month=1)
        elif schedule == 'weekly':
            week_day = today.weekday()
            date_from = today + relativedelta(days=-week_day)
        elif schedule == 'bi-weekly':
            week = int(today.strftime("%U") if week_start == '7' else today.strftime("%W"))
            week_day = today.weekday()
            is_second_week = week % 2 == 0
            date_from = today + relativedelta(days=-week_day - 7 * int(is_second_week))
        elif schedule == 'bi-monthly':
            current_year_slice = math.ceil(today.month / 2)
            date_from = today.replace(day=1, month=(current_year_slice - 1) * 2 + 1)
        else:
            date_from = today.replace(day=1)
        if self.contract_id and date_from < self.contract_id.date_start:
            date_from = self.contract_id.date_start
        return date_from

    @api.depends('contract_id', 'struct_id')
    def _compute_date_from(self):
        for payslip in self:
            if self.env.context.get('default_date_from'):
                payslip.date_from = self.env.context.get('default_date_from')
            else:
                payslip.date_from = payslip._get_schedule_period_start()

    def _get_schedule_timedelta(self):
        self.ensure_one()
        schedule = self.contract_id.schedule_pay or self.contract_id.structure_type_id.default_schedule_pay
        if schedule == 'quarterly':
            timedelta = relativedelta(months=3, days=-1)
        elif schedule == 'semi-annually':
            timedelta = relativedelta(months=6, days=-1)
        elif schedule == 'annually':
            timedelta = relativedelta(years=1, days=-1)
        elif schedule == 'weekly':
            timedelta = relativedelta(days=6)
        elif schedule == 'bi-weekly':
            timedelta = relativedelta(days=13)
        elif schedule == 'semi-monthly':
            timedelta = relativedelta(day=15 if self.date_from.day < 15 else 31)
        elif schedule == 'bi-monthly':
            timedelta = relativedelta(months=2, days=-1)
        elif schedule == 'daily':
            timedelta = relativedelta(days=0)
        else:
            timedelta = relativedelta(months=1, days=-1)
        return timedelta

    @api.depends('date_from', 'contract_id', 'struct_id')
    def _compute_date_to(self):
        for payslip in self:
            if self.env.context.get('default_date_to'):
                payslip.date_to = self.env.context.get('default_date_to')
            else:
                payslip.date_to = payslip.date_from and payslip.date_from + payslip._get_schedule_timedelta()
            if payslip.contract_id and payslip.contract_id.date_end and payslip.date_from and payslip.date_from >= payslip.contract_id.date_start and payslip.date_from < payslip.contract_id.date_end and payslip.date_to > payslip.contract_id.date_end:
                payslip.date_to = payslip.contract_id.date_end

    @api.depends('employee_id', 'contract_id', 'struct_id', 'date_from', 'date_to', 'struct_id')
    def _compute_input_line_ids(self):
        attachment_type_ids = self.env['hr.payslip.input.type'].search([('available_in_attachments', '=', True)]).ids
        for slip in self:
            if not slip.employee_id or not slip.employee_id.salary_attachment_ids or not slip.struct_id:
                lines_to_remove = slip.input_line_ids.filtered(lambda x: x.input_type_id.id in attachment_type_ids)
                slip.update({'input_line_ids': [Command.unlink(line.id) for line in lines_to_remove]})
            if slip.employee_id.salary_attachment_ids and slip.date_to:
                lines_to_remove = slip.input_line_ids.filtered(lambda x: x.input_type_id.id in attachment_type_ids)
                input_line_vals = [Command.unlink(line.id) for line in lines_to_remove]
                valid_attachments = slip.employee_id.salary_attachment_ids.filtered(
                    lambda a: a.state == 'open' and a.date_start <= slip.date_to and (not a.date_end or a.date_end >= slip.date_from) and (not a.other_input_type_id.struct_ids or slip.struct_id in a.other_input_type_id.struct_ids)
                )
                for input_type_id, attachments in valid_attachments.grouped("other_input_type_id").items():
                    amount = attachments._get_active_amount()
                    name = ', '.join(attachments.mapped('description'))
                    input_line_vals.append(Command.create({
                        'name': name,
                        'amount': amount if not slip.credit_note else -amount,
                        'input_type_id': input_type_id.id,
                    }))
                slip.update({'input_line_ids': input_line_vals})

    @api.depends('salary_attachment_ids')
    def _compute_salary_attachment_count(self):
        for slip in self:
            slip.salary_attachment_count = len(slip.salary_attachment_ids)

    @api.depends('employee_id', 'state')
    def _compute_negative_net_to_report_display(self):
        activity_type = self.env.ref('hr_payroll.mail_activity_data_hr_payslip_negative_net', raise_if_not_found=False) or self.env['mail.activity.type']
        for payslip in self:
            if payslip.state in ['draft', 'verify']:
                payslips_to_report = self.env['hr.payslip'].search([
                    ('has_negative_net_to_report', '=', True),
                    ('employee_id', 'in', payslip.employee_id.ids),
                    ('credit_note', '=', False),
                ])
                payslip.negative_net_to_report_display = payslips_to_report
                payslip.negative_net_to_report_amount = payslips_to_report._get_line_values(['NET'], compute_sum=True)['NET']['sum']['total']
                payslip.negative_net_to_report_message = _('Note: There are previous payslips with a negative amount for a total of %s to report.', round(payslip.negative_net_to_report_amount, 2))
            else:
                payslip.negative_net_to_report_display = False
                payslip.negative_net_to_report_amount = False
                payslip.negative_net_to_report_message = False

    def _get_negative_net_input_type(self):
        self.ensure_one()
        return self.env.ref('hr_payroll.input_deduction', raise_if_not_found=False) or self.env['hr.payslip.input.type']

    def action_report_negative_amount(self):
        self.ensure_one()
        deduction_input_type = self._get_negative_net_input_type()
        deduction_input_line = self.input_line_ids.filtered(lambda l: l.input_type_id == deduction_input_type)
        if deduction_input_line:
            deduction_input_line.amount += abs(self.negative_net_to_report_amount)
        else:
            self.write({'input_line_ids': [(0, 0, {'input_type_id': deduction_input_type.id, 'amount': abs(self.negative_net_to_report_amount)})]})
            self.compute_sheet()
        self.env['hr.payslip'].search([
            ('has_negative_net_to_report', '=', True),
            ('employee_id', '=', self.employee_id.id),
            ('credit_note', '=', False),
        ]).write({'has_negative_net_to_report': False})

    def _compute_is_regular(self):
        for payslip in self:
            payslip.is_regular = payslip.struct_id.type_id.default_struct_id == payslip.struct_id

    def _is_invalid(self):
        self.ensure_one()
        if self.state not in ['done', 'paid']:
            return _("La nomina debe estar en estado 'Hecha' o 'Pagada' para poder imprimir el recibo de pago.")
        return False

    @api.depends('worked_days_line_ids', 'input_line_ids')
    def _compute_line_ids(self):
        if not self.env.context.get("payslip_no_recompute"):
            return
        payslips = self.filtered(lambda p: p.line_ids and p.state in ['draft', 'verify'])
        payslips.line_ids.unlink()
        self.env['hr.payslip.line'].create(payslips._get_payslip_lines())

    @api.depends('line_ids.total')
    def _compute_basic_net(self):
        for payslip in self:
            values = payslip._get_line_values(['SMENS', 'TOTAL_ASIG', 'TOTAL_DED'])
            basic = values['SMENS'][payslip.id]['total']
            gross = values['TOTAL_ASIG'][payslip.id]['total']
            deductions = values['TOTAL_DED'][payslip.id]['total']
            net = gross - deductions
            payslip.basic_wage = basic
            payslip.gross_wage = gross
            payslip.net_wage = net
            payslip.net_wage_usd = (net / payslip.tasa_cambio) if payslip.tasa_cambio else 0.0

    @api.depends('worked_days_line_ids.number_of_hours', 'worked_days_line_ids.is_paid', 'worked_days_line_ids.is_credit_time')
    def _compute_worked_hours(self):
        for payslip in self:
            payslip.sum_worked_hours = sum([line.number_of_hours for line in payslip.worked_days_line_ids if not line.is_credit_time])

    def _get_regular_worked_hours(self):
        self.ensure_one()
        return self.sum_worked_hours

    def _compute_is_superuser(self):
        self.is_superuser = self.env.user._is_superuser() and self.env.user.has_group('base.group_no_one')

    def _compute_has_refund_slip(self):
        for payslip in self:
            if not payslip.credit_note and payslip.state in ('done', 'paid') and self.search_count([
                ('employee_id', '=', payslip.employee_id.id),
                ('date_from', '=', payslip.date_from),
                ('date_to', '=', payslip.date_to),
                ('contract_id', '=', payslip.contract_id.id),
                ('struct_id', '=', payslip.struct_id.id),
                ('credit_note', '=', True),
                ('state', '!=', 'cancel'),
            ]):
                payslip.has_refund_slip = True
            else:
                payslip.has_refund_slip = False

    @api.constrains('date_from', 'date_to')
    def _check_dates(self):
        if any(payslip.date_from > payslip.date_to for payslip in self):
            raise ValidationError(_("Payslip 'Date From' must be earlier than 'Date To."))

    def _get_pdf_reports(self):
        default_report = self.env.ref(
            'venrides_payroll.action_report_payslip_venezuela', raise_if_not_found=False
        )
        result = defaultdict(lambda: self.env['hr.payslip'])
        for payslip in self:
            if not payslip.struct_id or not payslip.struct_id.report_id:
                result[default_report] |= payslip
            else:
                result[payslip.struct_id.report_id] |= payslip
        return result

    @api.model
    def _get_email_template(self):
        return self.env.ref('hr_payroll.mail_template_new_payslip', raise_if_not_found=False)

    def _generate_pdf(self):
        mapped_reports = self._get_pdf_reports()
        attachments_vals_list = []
        generic_name = _("Payslip")
        template = self._get_email_template()
        for report, payslips in mapped_reports.items():
            for payslip in payslips:
                pdf_content, dummy = self.env['ir.actions.report'].sudo().with_context(lang=payslip.employee_id.lang or self.env.lang)._render_qweb_pdf(report, payslip.id)
                if report.print_report_name:
                    pdf_name = safe_eval(report.print_report_name, {'object': payslip})
                else:
                    pdf_name = generic_name
                attachments_vals_list.append({
                    'name': pdf_name,
                    'type': 'binary',
                    'raw': pdf_content,
                    'res_model': payslip._name,
                    'res_id': payslip.id,
                })
                if template:
                    template.send_mail(payslip.id, email_layout_xmlid='mail.mail_notification_light')
        self.env['ir.attachment'].sudo().create(attachments_vals_list)

    def _filter_out_of_contracts_payslips(self):
        return self.filtered(lambda p: p.contract_id and (p.contract_id.date_start > p.date_to or (p.contract_id.date_end and p.contract_id.date_end < p.date_from)))

    def action_payslip_done(self):
        invalid_payslips = self._filter_out_of_contracts_payslips()
        if invalid_payslips:
            raise ValidationError(_('The following employees have a contract outside of the payslip period:\n%s', '\n'.join(invalid_payslips.mapped('employee_id.name'))))
        if any(slip.contract_id.state == 'cancel' for slip in self):
            raise ValidationError(_('You cannot validate a payslip on which the contract is cancelled'))
        if any(slip.state == 'cancel' for slip in self):
            raise ValidationError(_("You can't validate a cancelled payslip."))
        if mismatched_slips := self.filtered(lambda slip: slip.payslip_run_id and slip.company_id != slip.payslip_run_id.company_id):
            raise ValidationError(_(
                "The following payslips company differs from the batch's company:\n%s", "\n".join(mismatched_slips.mapped('number')))
            )
        self.write({'state': 'done'})

        line_values = self._get_line_values(['NET'])

        self.filtered(lambda p: not p.credit_note and line_values['NET'][p.id]['total'] < 0).write({'has_negative_net_to_report': True})
        self.mapped('payslip_run_id').action_close()
        regular_payslips = self.filtered(lambda p: p.struct_id.type_id.default_struct_id == p.struct_id)
        work_entries = self.env['hr.work.entry']
        if work_entries._fields.get('date_start') and hasattr(work_entries, 'action_validate'):
            for regular_payslip in regular_payslips:
                work_entries |= self.env['hr.work.entry'].search([
                    ('date_start', '<=', regular_payslip.date_to),
                    ('date_stop', '>=', regular_payslip.date_from),
                    ('employee_id', '=', regular_payslip.employee_id.id),
                ])
            if work_entries:
                work_entries.action_validate()

        if self.env.context.get('payslip_generate_pdf'):
            if self.env.context.get('payslip_generate_pdf_direct'):
                self._generate_pdf()
            else:
                self.write({'queued_for_pdf': True})
                payslip_cron = self.env.ref('hr_payroll.ir_cron_generate_payslip_pdfs', raise_if_not_found=False)
                if payslip_cron:
                    payslip_cron._trigger()

    def action_payslip_cancel(self):
        payroll_manager = self.env.ref('hr.payroll.group_hr_payroll_manager', raise_if_not_found=False)
        is_payroll_manager = bool(payroll_manager) and payroll_manager in self.env.user.groups_id
        if not is_payroll_manager and self.filtered(lambda slip: slip.state == 'done'):
            raise UserError(_("Cannot cancel a payslip that is done."))
        self.write({'state': 'cancel'})
        self.mapped('payslip_run_id').action_close()

    def action_payslip_paid(self):
        if any(slip.state not in ['done', 'paid'] for slip in self):
            raise UserError(_('Cannot mark payslip as paid if not confirmed.'))
        self.filtered(lambda p: p.state != 'paid').write({
            'state': 'paid',
            'paid_date': fields.Date.today(),
        })

    def action_payslip_payment_report(self, export_format='csv'):
        self.ensure_one()
        if len(self.payslip_run_id) > 1:
            raise UserError(_('The selected payslips should be linked to the same batch'))
        return {
            'name': self.env._('Generate a Payment Report'),
            'type': 'ir.actions.act_window',
            'res_model': 'hr.payslip.payment.report.wizard',
            'view_mode': 'form',
            'views': [(False, 'form')],
            'target': 'new',
            'context': {
                'default_payslip_ids': self.ids,
                'default_payslip_run_id': self.payslip_run_id.id,
                'default_export_format': export_format,
            },
        }

    def action_payslip_unpaid(self):
        if any(slip.state != 'paid' for slip in self):
            raise UserError(_('You cannot cancel the payment if the payslip has not been paid.'))
        self.write({'state': 'done'})
        self.payslip_run_id.write({'state': 'close'})

    def action_open_work_entries(self):
        self.ensure_one()
        return self.employee_id.action_open_work_entries(initial_date=self.date_from)

    def action_open_salary_attachments(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': _('Salary Attachments'),
            'res_model': 'hr.salary.attachment',
            'view_mode': 'list,form',
            'domain': [('id', 'in', self.salary_attachment_ids.ids)],
        }

    def refund_sheet(self):
        copied_payslips = self.env['hr.payslip']
        for payslip in self:
            copied_payslip = payslip.copy({
                'credit_note': True,
                'name': _('Refund: %(payslip)s', payslip=payslip.name),
                'edited': True,
                'state': 'verify',
            })
            for wd in copied_payslip.worked_days_line_ids:
                wd.number_of_hours = -wd.number_of_hours
                wd.number_of_days = -wd.number_of_days
                wd.amount = -wd.amount
            for line in copied_payslip.line_ids:
                line.amount = -line.amount
                line.total = -line.total
            copied_payslips |= copied_payslip
        formview_ref = self.env.ref('venrides_payroll.hr_payslip_form_inherit_views_lunes', False)
        treeview_ref = self.env.ref('venrides_payroll.hr_payslip_tree_inherit_views_totales', False)
        return {
            'name': ("Refund Payslip"),
            'view_mode': 'list, form',
            'view_id': False,
            'res_model': 'hr.payslip',
            'type': 'ir.actions.act_window',
            'target': 'current',
            'domain': [('id', 'in', copied_payslips.ids)],
            'views': [(treeview_ref and treeview_ref.id or False, 'list'), (formview_ref and formview_ref.id or False, 'form')],
            'context': {}
        }

    @api.ondelete(at_uninstall=False)
    def _unlink_if_draft_or_cancel(self):
        if any(payslip.state not in ('draft', 'cancel') for payslip in self):
            raise UserError(_('You cannot delete a payslip which is not draft or cancelled!'))

    def compute_sheet(self):
        payslips = self.filtered(lambda slip: slip.state in ['draft', 'verify'])
        payslips.line_ids.unlink()
        self.env.flush_all()
        today = fields.Date.today()
        for payslip in payslips:
            number = payslip.number or self.env['ir.sequence'].next_by_code('salary.slip')
            payslip.write({
                'number': number,
                'state': 'verify',
                'compute_date': today
            })
        self.env['hr.payslip.line'].create(payslips._get_payslip_lines())
        if any(payslips.mapped('ytd_computation')):
            self._compute_worked_days_ytd()
        return True

    def action_refresh_from_work_entries(self):
        if any(p.state not in ['draft', 'verify'] for p in self):
            raise UserError(_('The payslips should be in Draft or Waiting state.'))
        payslips = self.filtered(lambda p: not p.edited)
        payslips.mapped('worked_days_line_ids').unlink()
        payslips.mapped('line_ids').unlink()
        payslips._compute_worked_days_line_ids()
        payslips.compute_sheet()

    def _round_days(self, work_entry_type, days):
        if work_entry_type.round_days != 'NO':
            precision_rounding = 0.5 if work_entry_type.round_days == "HALF" else 1
            day_rounded = float_round(days, precision_rounding=precision_rounding, rounding_method=work_entry_type.round_days_type)
            return day_rounded
        return days

    def _get_worked_day_lines_hours_per_day(self):
        self.ensure_one()
        work_calendar = self.contract_id.resource_calendar_id or self.employee_id.resource_calendar_id or self.company_id.resource_calendar_id
        return work_calendar.hours_per_day if work_calendar else 8.0

    def _get_out_of_contract_calendar(self):
        self.ensure_one()
        if self.contract_id.time_credit:
            return self.contract_id.standard_calendar_id
        return self.contract_id.resource_calendar_id or self.employee_id.resource_calendar_id or self.company_id.resource_calendar_id

    def _get_worked_day_lines_values(self, domain=None):
        self.ensure_one()
        res = []
        hours_per_day = self._get_worked_day_lines_hours_per_day()
        work_hours = self.contract_id.get_work_hours(self.date_from, self.date_to, domain=domain)
        work_hours_ordered = sorted(work_hours.items(), key=lambda x: x[1])
        biggest_work = work_hours_ordered[-1][0] if work_hours_ordered else 0
        add_days_rounding = 0
        for work_entry_type_id, hours in work_hours_ordered:
            work_entry_type = self.env['hr.work.entry.type'].browse(work_entry_type_id)
            days = round(hours / hours_per_day, 5) if hours_per_day else 0
            if work_entry_type_id == biggest_work:
                days += add_days_rounding
            day_rounded = self._round_days(work_entry_type, days)
            add_days_rounding += (days - day_rounded)
            attendance_line = {
                'sequence': work_entry_type.sequence,
                'work_entry_type_id': work_entry_type_id,
                'number_of_days': day_rounded,
                'number_of_hours': hours,
            }
            res.append(attendance_line)
        work_entry_type = self.env['hr.work.entry.type']
        return sorted(res, key=lambda d: work_entry_type.browse(d['work_entry_type_id']).sequence)

    def _get_worked_day_lines(self, domain=None, check_out_of_contract=True):
        res = []
        self.ensure_one()
        contract = self.contract_id
        res = self._get_worked_day_lines_values(domain=domain)
        if not check_out_of_contract:
            return res
        out_days, out_hours = 0, 0
        reference_calendar = self._get_out_of_contract_calendar()
        if self.date_from < contract.date_start:
            start = fields.Datetime.to_datetime(self.date_from)
            stop = min(fields.Datetime.to_datetime(contract.date_start) + relativedelta(days=-1, hour=23, minute=59), fields.Datetime.to_datetime(self.date_to) + relativedelta(hour=23, minute=59))
            out_time = reference_calendar.get_work_duration_data(start, stop, compute_leaves=False, domain=['|', ('work_entry_type_id', '=', False), ('work_entry_type_id.is_leave', '=', False)])
            out_days += out_time['days']
            out_hours += out_time['hours']
        if contract.date_end and contract.date_end < self.date_to:
            start = max(fields.Datetime.to_datetime(contract.date_end) + relativedelta(days=1), fields.Datetime.to_datetime(self.date_from))
            stop = fields.Datetime.to_datetime(self.date_to) + relativedelta(hour=23, minute=59)
            out_time = reference_calendar.get_work_duration_data(start, stop, compute_leaves=False, domain=['|', ('work_entry_type_id', '=', False), ('work_entry_type_id.is_leave', '=', False)])
            out_days += out_time['days']
            out_hours += out_time['hours']
        work_entry_type = self.env.ref('hr_payroll.hr_work_entry_type_out_of_contract', raise_if_not_found=False)
        if work_entry_type and (out_days or out_hours):
            res.append({
                'sequence': work_entry_type.sequence,
                'work_entry_type_id': work_entry_type.id,
                'number_of_days': out_days,
                'number_of_hours': out_hours,
            })
        return res

    @property
    def paid_amount(self):
        self.ensure_one()
        return self._get_paid_amount()

    @property
    def is_outside_contract(self):
        self.ensure_one()
        return self._is_outside_contract_dates()

    def _is_outside_contract_dates(self):
        self.ensure_one()
        contract = self.contract_id
        if not contract:
            return False
        return bool(
            (contract.date_start and contract.date_start > self.date_to)
            or (contract.date_end and contract.date_end < self.date_from)
        )

    def _rule_parameter(self, code, reference_date=False):
        self.ensure_one()
        if reference_date:
            return self.env['hr.rule.parameter']._get_parameter_from_code(code, reference_date)
        else:
            return self.env['hr.rule.parameter']._get_parameter_from_code(code, self.date_to)

    def _sum(self, code, from_date, to_date=None):
        if to_date is None:
            to_date = fields.Date.today()
        self.env.cr.execute("""
            SELECT sum(pl.total)
            FROM hr_payslip as hp, hr_payslip_line as pl
            WHERE hp.employee_id = %s
            AND hp.state in ('done', 'paid')
            AND hp.date_from >= %s
            AND hp.date_to <= %s
            AND hp.id = pl.slip_id
            AND pl.code = %s""", (self.employee_id.id, from_date, to_date, code))
        res = self.env.cr.fetchone()
        return res and res[0] or 0.0

    def sum(self, code, from_date, to_date=None):
        """Alias usado por las reglas salariales."""
        return self._sum(code, from_date, to_date=to_date)

    def _get_base_local_dict(self):
        return {
            'float_round': float_round,
            'float_compare': float_compare,
            'relativedelta': relativedelta,
            'ceil': __import__('math').ceil,
            'floor': __import__('math').floor,
            'UserError': UserError,
            'date': date,
            'datetime': datetime,
            'defaultdict': defaultdict,
        }

    def _get_rule_name(self, localdict, rule, employee_lang):
        return rule.with_context(lang=employee_lang).name

    def _get_localdict(self):
        self.ensure_one()
        same_type_input_lines = defaultdict(lambda x: self.env['hr.payslip.input'])
        input_line_ids_by_code = self.input_line_ids.grouped('code')
        for code, input_lines in input_line_ids_by_code.items():
            if len(input_lines) > 1:
                same_type_input_lines[code] = input_lines
        localdict = {
            **self._get_base_local_dict(),
            **{
                'categories': _AttrDict(),
                'rules': _AttrDict(),
                'payslip': self,
                'worked_days': _AttrDict(
                    {line.code: line for line in self.worked_days_line_ids if line.code},
                    default=False),
                'inputs': _AttrDict(
                    {line.code: line for line in self.input_line_ids if line.code},
                    default=False),
                'employee': self.employee_id,
                'contract': self.contract_id,
                'same_type_input_lines': same_type_input_lines,
                'result_rules': {},
            }
        }
        return localdict

    def _get_payslip_lines(self):
        line_vals = []
        for payslip in self:
            if not payslip.contract_id:
                raise UserError(_("There's no contract set on payslip %s for %s. Check that there is at least a contract set on the employee form.", payslip.name, payslip.employee_id.name))
            localdict = self.env.context.get('force_payslip_localdict', None)
            if localdict is None:
                localdict = payslip._get_localdict()
            rules_dict = localdict['rules']
            result_rules_dict = localdict['result_rules']
            blacklisted_rule_ids = self.env.context.get('prevent_payslip_computation_line_ids', [])
            result = {}
            for rule in sorted(payslip.struct_id.rule_ids, key=lambda x: x.sequence):
                if rule.id in blacklisted_rule_ids:
                    continue
                localdict.update({
                    'result': None,
                    'result_qty': 1.0,
                    'result_rate': 100,
                    'result_name': False,
                })
                if rule._satisfy_condition(localdict):
                    employee_lang = payslip.employee_id.lang or self.env.lang
                    if rule.code in localdict['same_type_input_lines']:
                        for multi_line_rule in localdict['same_type_input_lines'][rule.code]:
                            localdict['inputs'][rule.code] = multi_line_rule
                            amount, qty, rate = rule._compute_rule(localdict)
                            tot_rule = amount * qty * rate / 100.0
                            localdict = rule.category_id._sum_salary_rule_category(localdict, tot_rule)
                            rule_name = payslip._get_rule_name(localdict, rule, employee_lang)
                            line_vals.append({
                                'sequence': rule.sequence,
                                'code': rule.code,
                                'name': rule_name,
                                'salary_rule_id': rule.id,
                                'contract_id': localdict['contract'].id,
                                'employee_id': localdict['employee'].id,
                                'amount': amount,
                                'quantity': qty,
                                'rate': rate,
                                'slip_id': payslip.id,
                                'total': tot_rule,
                            })
                    else:
                        amount, qty, rate = rule._compute_rule(localdict)
                        previous_amount = 0.0
                        tot_rule = amount * qty * rate / 100.0
                        localdict[rule.code] = tot_rule
                        result_rules_dict[rule.code] = {'total': tot_rule, 'amount': amount, 'quantity': qty}
                        rules_dict[rule.code] = rule
                        localdict = rule.category_id._sum_salary_rule_category(localdict, tot_rule - previous_amount)
                        rule_name = payslip._get_rule_name(localdict, rule, employee_lang)
                        result[rule.code] = {
                        'sequence': rule.sequence,
                        'code': rule.code,
                        'name': rule_name,
                        'salary_rule_id': rule.id,
                        'contract_id': localdict['contract'].id,
                        'employee_id': localdict['employee'].id,
                        'amount': amount,
                        'quantity': qty,
                        'rate': rate,
                        'slip_id': payslip.id,
                        'total': tot_rule,
                    }
            line_vals += list(result.values())
        return line_vals
