# -*- coding: utf-8 -*-
from markupsafe import Markup

from odoo import api, fields, models


class VenridesContractTemplate(models.Model):
    _name = 'venrides.contract.template'
    _description = 'Plantilla de contrato'
    _order = 'code, version desc'
    _rec_name = 'display_name_full'

    code = fields.Char(string='Código', required=True)
    name = fields.Char(string='Nombre', required=True)
    display_name_full = fields.Char(
        string='Plantilla', compute='_compute_display_name_full', store=True)
    version = fields.Integer(string='Versión', default=1, required=True)
    parent_id = fields.Many2one(
        'venrides.contract.template', string='Versión anterior', readonly=True)
    root_id = fields.Many2one(
        'venrides.contract.template', string='Plantilla raíz',
        compute='_compute_root_id', store=True)
    contract_type_id = fields.Many2one(
        'hr.contract.type', string='Tipo de contrato', required=True)
    job_ids = fields.Many2many(
        'hr.job', 'venrides_template_job_rel', 'template_id', 'job_id',
        string='Puestos aplicables')
    body_html = fields.Html(
        string='Cuerpo del contrato',
        help='Usa los marcadores ${empleado}, ${cedula}, ${cargo}, ${sueldo}, '
             '${fecha_inicio}, ${fecha_fin}, ${jornada}, ${empresa}, ${rif}, '
             '${numero_contrato}, ${bono_guerra}, ${bono_transporte}, '
             '${bono_desempeno}, ${cestaticket}, ${total}.')
    clause_ids = fields.Many2many(
        'venrides.contract.clause', 'venrides_template_clause_rel',
        'template_id', 'clause_id', string='Cláusulas')
    annex_ids = fields.Many2many(
        'venrides.contract.annex', 'venrides_template_annex_rel',
        'template_id', 'annex_id', string='Anexos')
    salary_table_id = fields.Many2one(
        'venrides.salary.table', string='Tabla salarial')
    is_current = fields.Boolean(string='Vigente', default=True)
    active = fields.Boolean(default=True)
    sequence = fields.Integer(default=10)
    company_id = fields.Many2one(
        'res.company', default=lambda self: self.env.company)
    contract_count = fields.Integer(compute='_compute_contract_count')

    _code_version_uniq = models.Constraint(
        'unique(code, version)', 'Ya existe una versión con ese código.')

    @api.depends('code', 'name', 'version')
    def _compute_display_name_full(self):
        for template in self:
            template.display_name_full = '%s v%s — %s' % (
                template.code or '', template.version or 0, template.name or '')

    @api.depends('parent_id')
    def _compute_root_id(self):
        for template in self:
            template.root_id = template.parent_id.root_id or template.parent_id or template

    def _compute_contract_count(self):
        for template in self:
            template.contract_count = self.env['hr.contract'].search_count(
                [('template_id', '=', template.id)])

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            if not vals.get('version'):
                last = self.search(
                    [('code', '=', vals.get('code'))], order='version desc', limit=1)
                vals['version'] = (last.version + 1) if last else 1
        return super().create(vals_list)

    def action_new_version(self):
        self.ensure_one()
        new = self.copy({
            'version': self.version + 1,
            'parent_id': self.id,
            'is_current': True,
            'name': self.name,
        })
        self.write({'is_current': False})
        return {
            'type': 'ir.actions.act_window',
            'res_model': 'venrides.contract.template',
            'res_id': new.id,
            'view_mode': 'form',
            'target': 'current',
        }

    def action_view_contracts(self):
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': 'Contratos con esta plantilla',
            'res_model': 'hr.contract',
            'view_mode': 'list,form',
            'domain': [('template_id', '=', self.id)],
        }

    def _render_values(self, contract):
        company = contract.company_id or self.env.company
        employee = contract.employee_id
        return {
            '${empresa}': company.name or '',
            '${rif}': company.vat or '',
            '${domicilio}': ' '.join(filter(None, [
                company.street or '', company.street2 or '', company.city or '',
                company.state_id.name or '', company.country_id.name or ''])),
            '${empleado}': employee.name or '',
            '${cedula}': employee.identification_id or '',
            '${cargo}': (contract.job_id.name or employee.job_title or ''),
            '${departamento}': contract.department_id.name or '',
            '${numero_contrato}': contract.contract_number or '',
            '${fecha_inicio}': contract.date_start.strftime('%d/%m/%Y') if contract.date_start else '',
            '${fecha_fin}': contract.date_end.strftime('%d/%m/%Y') if contract.date_end else 'indefinida',
            '${jornada}': contract.schedule_description or '',
            '${sueldo}': '%.2f' % (contract.wage_usd or 0.0),
            '${bono_guerra}': '%.2f' % (contract.bono_guerra_usd or 0.0),
            '${bono_transporte}': '%.2f' % (contract.bono_transporte_usd or 0.0),
            '${bono_desempeno}': '%.2f' % (contract.bono_desempeno_max_usd or 0.0),
            '${cestaticket}': '%.2f' % (contract.cestaticket_usd or 0.0),
            '${total}': '%.2f' % (contract.total_package_usd or 0.0),
        }

    def _render_text(self, text, contract):
        body = text or ''
        for key, value in self._render_values(contract).items():
            body = body.replace(key, value)
        return Markup(body)

    def _render_body(self, contract):
        self.ensure_one()
        return self._render_text(self.body_html, contract)
