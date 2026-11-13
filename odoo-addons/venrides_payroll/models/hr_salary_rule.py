from odoo import models, fields, api, _
from odoo.exceptions import UserError
from odoo.tools.safe_eval import safe_eval


class HRRule(models.Model):
    _name = 'hr.salary.rule'
    _description = 'Salary Rule'

    struct_id = fields.Many2one('hr.payroll.structure', string='Structure', required=True, ondelete='cascade')
    active = fields.Boolean(string='Active', default=True)

    category_id = fields.Many2one('hr.salary.rule.category', string='Category')
    name = fields.Char(string='Name', required=True)
    code = fields.Char(string='Code')
    condition_select = fields.Selection([
        ('none', 'None'),
        ('python', 'Python'),
        ('category', 'Category'),
        ('direct', 'Direct'),
    ], string='Condition Select', default='none')
    condition_python = fields.Text(string='Condition Python')
    amount_select = fields.Selection([
        ('none', 'None'),
        ('code', 'Code'),
        ('python', 'Python'),
        ('fix', 'Fixed'),
    ], string='Amount Select', default='none')
    amount_python_compute = fields.Text(string='Amount Python Compute')
    appears_on_payslip = fields.Boolean(string='Appears on Payslip', default=True)
    sequence = fields.Integer(string='Sequence', default=10)

    origin_partner = fields.Selection(
        selection=[('empleado', 'Empleado'),
                   ('empresa', 'Empresa'),
                   ('otro', 'Otro Tercero')],
        string='Tipo de tercero', required=True, default="otro")

    partner_id = fields.Many2one('res.partner', 'Tercero')

    mostrar_cantidad = fields.Selection(
        selection=[('dias', 'Días'),
                     ('horas', 'Horas')], string='Mostrar cantidad')

    def _satisfy_condition(self, localdict):
        self.ensure_one()
        if self.condition_select == 'none':
            return True
        if self.condition_select == 'python':
            try:
                safe_eval(self.condition_python or 'result = False', localdict,
                          mode='exec', filename='%s/%s' % (self._name, self.id))
            except Exception as exc:  # noqa: BLE001
                raise UserError(_('Error al evaluar la condición de la regla %(rule)s:\n%(error)s',
                                  rule=self.name, error=exc)) from exc
            return bool(localdict.get('result'))
        return True

    def _compute_rule(self, localdict):
        self.ensure_one()
        localdict.setdefault('result', 0.0)
        localdict.setdefault('result_qty', 1.0)
        localdict.setdefault('result_rate', 100.0)
        if self.amount_select in ('code', 'python'):
            try:
                safe_eval(self.amount_python_compute or 'result = 0.0', localdict,
                          mode='exec', filename='%s/%s' % (self._name, self.id))
            except Exception as exc:  # noqa: BLE001
                raise UserError(_('Error al calcular la regla %(rule)s:\n%(error)s',
                                  rule=self.name, error=exc)) from exc
        amount = float(localdict.get('result') or 0.0)
        qty = float(localdict.get('result_qty') or 1.0)
        rate = float(localdict.get('result_rate') if localdict.get('result_rate') is not None else 100.0)
        return amount, qty, rate


class HRRuleCategory(models.Model):
    _name = 'hr.salary.rule.category'
    _description = 'Salary Rule Category'

    name = fields.Char(string='Name', required=True)
    code = fields.Char(string='Code', required=True)

    def _sum_salary_rule_category(self, localdict, amount):
        """Acumula el importe de la regla en su categoría dentro del localdict."""
        categories = localdict.setdefault('categories', {})
        categories[self.code] = categories.get(self.code, 0.0) + amount
        return localdict
