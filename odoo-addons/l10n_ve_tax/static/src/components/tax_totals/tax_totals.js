/** @odoo-module **/

import { registry } from "@web/core/registry";
import { standardFieldProps } from "@web/views/fields/standard_field_props";

import { TaxTotalsComponent } from "@account/components/tax_totals/tax_totals";

/**
 * Widget de totales en doble moneda (Bs / Divisa) para facturas mucousas.
 *
 * Migracion Odoo 20:
 *  - El nucleo define `totals = computed(() => this.formatData(this.props))`.
 *    La version anterior de este archivo asignaba `this.totals = totals` dentro de
 *    formatData(), lo que SOBRESCRIBIA el signal computed por un objeto plano
 *    (destruyendo la reactividad) y ademas devolvia `undefined` en todas sus ramas.
 *    Ademas recalculaba amount_total/subtotals ignorando los valores
 *    base_amount_currency / tax_amount_currency del backend.
 *  - formatData() ahora delega en el nucleo y DEVUELVE el objeto, que es el
 *    contrato real del metodo. Todos los campos `foreign_*` (foreign_subtotals,
 *    groups_by_foreign_subtotal, foreign_formatted_*) ya los calcula el backend en
 *    l10n_ve_tax/models/account_tax.py, por lo que no hace falta recalcularlos aqui.
 */
export class TaxTotalsComponents extends TaxTotalsComponent {
    get currencyId() {
        return this.props.record.data.foreign_currency_id;
    }

    formatData(props) {
        return super.formatData(props);
    }
}

TaxTotalsComponents.template = "l10n_ve_tax.TaxForeignTotalsField";
TaxTotalsComponents.props = {
    ...standardFieldProps,
};

export const taxTotalsComponent = {
    component: TaxTotalsComponents,
};

registry.category("fields").add("account-tax-foreign-totals-field", taxTotalsComponent);