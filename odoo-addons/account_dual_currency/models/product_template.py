from odoo import api, fields, models, _
from odoo.exceptions import UserError, ValidationError

class Productos(models.Model):
    _inherit = 'product.template'

    currency_id_dif = fields.Many2one('res.currency', string='Moneda Diferente', compute='_compute_currency_id_dif')

    def _compute_currency_id_dif(self):
        for rec in self:
            rec.currency_id_dif = self.env.company.currency_id_dif.id

    cost_currency_id = fields.Many2one('res.currency', string="Moneda Local", compute='_compute_cost_currency_id')
    uom_name = fields.Char(related='uom_id.name', string="Nombre UoM")

    def _compute_cost_currency_id(self):
        # LocVe: auto-detección de moneda local (moneda base de la empresa)
        for rec in self:
            rec.cost_currency_id = rec.env.company.currency_id.id

    currency_usd_id = fields.Many2one('res.currency', string="Moneda USD", compute='_compute_currencies_strict')
    currency_bs_id = fields.Many2one('res.currency', string="Moneda Alterna", compute='_compute_currencies_strict')
    currency_alternate_name = fields.Char(string="Nombre Moneda Alterna", compute='_compute_currencies_strict')

    def _compute_currencies_strict(self):
        usd = self.env.ref('base.USD', raise_if_not_found=False) or self.env['res.currency'].search([('name', '=', 'USD')], limit=1)
        for rec in self:
            rec.currency_usd_id = usd.id if usd else False
            # La "moneda alterna" la define la compania: puede ser VES/VEF, USD
            # o cualquier otra. Antes estaba fija a VEF/VES, de modo que con una
            # base distinta el precio se rotulaba y formateaba en la moneda
            # equivocada.
            alterna = rec.company_id.currency_id_dif if rec.company_id else self.env.company.currency_id_dif
            if not alterna:
                alterna = self.env.ref('base.VEF', raise_if_not_found=False) or self.env['res.currency'].search([('name', 'in', ('VEF', 'VES'))], limit=1)
            rec.currency_bs_id = alterna.id if alterna else False
            rec.currency_alternate_name = (alterna.name or '') if alterna else ''

    # Campos maestros en USD
    list_price_usd = fields.Float(string="Precio Venta ($)", default=1.0)
    standard_price_usd = fields.Float(string="Costo en Divisa", default=0.0)

    # Sobreescribir list_price y standard_price nativos como calculados
    list_price = fields.Float(
        string='Sales Price',
        compute='_compute_list_price',
        inverse='_inverse_list_price',
        store=True,
        readonly=False
    )
    
    # Odoo 20 movio el costo maestro a la variante: 'product.product.standard_price'
    # es el campo almacenado (y company_dependent) y 'product.template.standard_price'
    # quedo como proxy que lee y escribe en sus variantes
    # ('_compute_template_field_from_variant_field' / '_set_product_variant_field').
    #
    # Antes LocVe redefinia el campo de la PLANTILLA como compute+store con un
    # inverse propio, con lo que las variantes nunca se actualizaban y se
    # quedaban en 0. La logica de doble moneda se aplica ahora sobre la
    # variante (ver models/product_product.py), y aqui se conserva la
    # definicion nativa para no romper la delegacion.
    #
    # El campo maestro en divisa sigue siendo 'standard_price_usd'.

    # 'list_price' es la MONEDA BASE y 'list_price_usd' el maestro en divisa.
    # La conversion se hace con la tasa BCV canonica (VES por USD) y NO con
    # 'get_trm_systray', que devuelve "alterna por base": con base USD ambas
    # coinciden, pero con base VES son reciprocas y el precio base salia
    # 36.5 veces mas pequeno.
    def _importe_en_base(self, importe_divisa, company):
        base = company.currency_id
        if base.name in ('USD', 'US$'):
            return importe_divisa
        bcv = self.env['res.currency']._tasa_bcv_ves_por_usd(company)
        return importe_divisa * bcv if bcv > 0 else importe_divisa

    def _importe_en_divisa(self, importe_base, company):
        base = company.currency_id
        if base.name in ('USD', 'US$'):
            return importe_base
        bcv = self.env['res.currency']._tasa_bcv_ves_por_usd(company)
        return importe_base / bcv if bcv > 0 else importe_base

    @api.depends('list_price_usd', 'company_id.currency_id')
    def _compute_list_price(self):
        for rec in self:
            company = rec.company_id or rec.env.company
            rec.list_price = self._importe_en_base(rec.list_price_usd, company)

    def _inverse_list_price(self):
        for rec in self:
            company = rec.company_id or rec.env.company
            val = self._importe_en_divisa(rec.list_price, company)
            if abs(rec.list_price_usd - val) > 1e-5:
                rec.list_price_usd = val

    # '_compute_standard_price' / '_inverse_standard_price' de la plantilla se
    # retiraron junto con el campo: en Odoo 20 son las nativas del core, que
    # delegan en las variantes. La conversion a divisa se aplica sobre
    # 'product.product.standard_price' (models/product_product.py).

    # Campos secundarios calculados para visualización, siempre expresados en la
    # MONEDA ALTERNA de la compania (currency_id_dif), que no siempre es Bs.
    #
    # 'list_price_bs' NO se almacena a proposito: depende de la TRM, que cambia
    # todos los dias. Al estar 'store=True' y depender solo de 'list_price',
    # quedaba congelado con la tasa del dia en que se calculo y mostraba un
    # precio en Bs desactualizado frente al precio base. Es un campo de
    # visualizacion (las vistas lo leen como readonly), asi que se recalcula en
    # cada lectura.
    # Float y NO Monetary: el precio alterno es base x TRM, y la TRM se
    # redondea a 4 decimales. Como Monetary heredaria los 2 decimales de VES
    # y 20 x 857.8876 = 17,157.752 se mostraria 17,157.75, perdiendo el 3er
    # decimal del redondeo de la tasa.
    list_price_bs = fields.Float(
        string='Precio Venta (Moneda Alterna)',
        compute='_compute_list_price_bs', store=False, digits=(16, 4)
    )

    standard_price_bs = fields.Float(
        string="Costo en Moneda Alterna",
        compute='_compute_standard_price_bs', digits=(16, 4)
    )

    def _tasa_alterna_por_base(self, rec):
        """Cuantas unidades de la moneda alterna vale 1 unidad de la base."""
        company = rec.company_id or self.env.company
        alterna = company.currency_id_dif
        if not alterna or alterna == company.currency_id:
            return 0.0
        tasa = self.env['res.currency'].get_trm_systray(company)
        return tasa if tasa and tasa > 0 else 0.0

    @api.depends('list_price', 'company_id')
    def _compute_list_price_bs(self):
        for rec in self:
            tasa = self._tasa_alterna_por_base(rec)
            # 'list_price' ya esta expresado en la MONEDA BASE de la compania.
            # Antes se multiplicaba 'list_price_usd', lo que solo era correcto
            # cuando la base era USD, y con base VES devolvia el valor base
            # rotulado como alterna.
            rec.list_price_bs = rec.list_price * tasa if tasa > 0 else 0.0

    @api.depends('standard_price_usd', 'company_id')
    def _compute_standard_price_bs(self):
        C = self.env['res.currency']
        for rec in self:
            company = rec.company_id or self.env.company
            base = company.currency_id
            alterna = company.currency_id_dif
            bcv = C._tasa_bcv_ves_por_usd(company)
            if not bcv or bcv <= 0:
                rec.standard_price_bs = 0.0
                continue
            # Costo en la MONEDA BASE, a partir del maestro en divisa.
            costo_base = rec.standard_price_usd if base.name in ('USD', 'US$') else rec.standard_price_usd * bcv
            # Costo en la MONEDA ALTERNA.
            if alterna and alterna.name in ('USD', 'US$'):
                rec.standard_price_bs = rec.standard_price_usd
            else:
                rec.standard_price_bs = costo_base * self._tasa_alterna_por_base(rec)

    price_with_tax_info = fields.Char(compute='_compute_price_with_tax_info')
    price_with_tax_bs = fields.Char(compute='_compute_price_with_tax_bs')

    @api.depends('list_price_usd', 'list_price_bs', 'taxes_id')
    def _compute_price_with_tax_info(self):
        for rec in self:
            total_usd = rec.list_price_usd
            total_bs = rec.list_price_bs
            if rec.taxes_id:
                try:
                    res_usd = rec.taxes_id.compute_all(rec.list_price_usd, quantity=1, product=rec)
                    total_usd = res_usd['total_included']
                    res_bs = rec.taxes_id.compute_all(rec.list_price_bs, quantity=1, product=rec)
                    total_bs = res_bs['total_included']
                except Exception:
                    pass
            rec.price_with_tax_info = f"(= $ {total_usd:,.2f} / Bs. {total_bs:,.2f} impuestos incluidos)".replace(',', 'X').replace('.', ',').replace('X', '.')

    @api.depends('list_price_bs', 'taxes_id')
    def _compute_price_with_tax_bs(self):
        for rec in self:
            total_bs = rec.list_price_bs
            if rec.taxes_id:
                try:
                    res_bs = rec.taxes_id.compute_all(rec.list_price_bs, quantity=1, product=rec)
                    total_bs = res_bs['total_included']
                except Exception:
                    pass
            rec.price_with_tax_bs = f"(= Bs. {total_bs:,.2f} impuestos incluidos)".replace(',', 'X').replace('.', ',').replace('X', '.')

    costo_reposicion_usd = fields.Monetary(string="Costo Reposición Alterno", currency_field='currency_id_dif')

    def _compania_de_creacion(self, vals):
        """Compania que aplica al producto en creacion.

        La TRM y la conversion dependen de la moneda base y la alterna de cada
        compania, asi que hay que usar la del PROPIO producto y no la del
        usuario en contexto: con una segunda compania, usar ``self.env.company``
        fijaba el precio en la moneda base equivocada.
        """
        if vals.get('company_id'):
            return self.env['res.company'].browse(vals['company_id'])
        return self.env.company

    @api.model_create_multi
    def create(self, vals_list):
        for vals in vals_list:
            company = self._compania_de_creacion(vals)
            if 'list_price_usd' in vals and 'list_price' not in vals:
                vals['list_price'] = self._importe_en_base(vals['list_price_usd'], company)
            if 'standard_price_usd' in vals and 'standard_price' not in vals:
                vals['standard_price'] = self._importe_en_base(vals['standard_price_usd'], company)
        return super().create(vals_list)

    def write(self, vals):
        if 'list_price_usd' in vals or 'standard_price_usd' in vals:
            for rec in self:
                company = rec.company_id or self.env.company
                if 'list_price_usd' in vals and 'list_price' not in vals:
                    vals['list_price'] = self._importe_en_base(vals['list_price_usd'], company)
                if 'standard_price_usd' in vals and 'standard_price' not in vals:
                    vals['standard_price'] = self._importe_en_base(vals['standard_price_usd'], company)
        return super().write(vals)


class ProductProduct(models.Model):
    _inherit = 'product.product'

    currency_id_dif = fields.Many2one(related='product_tmpl_id.currency_id_dif', readonly=True)
    cost_currency_id = fields.Many2one(related='product_tmpl_id.cost_currency_id', readonly=True)
    currency_usd_id = fields.Many2one(related='product_tmpl_id.currency_usd_id', readonly=True)
    currency_bs_id = fields.Many2one(related='product_tmpl_id.currency_bs_id', readonly=True)
    list_price_usd = fields.Float(related='product_tmpl_id.list_price_usd', readonly=False)
    standard_price_usd = fields.Float(related='product_tmpl_id.standard_price_usd', readonly=False)
    costo_reposicion_usd = fields.Monetary(related='product_tmpl_id.costo_reposicion_usd', readonly=False, currency_field='currency_usd_id')
    standard_price_bs = fields.Float(related='product_tmpl_id.standard_price_bs', readonly=False, digits=(16, 4))
