/** @odoo-module **/
import { registry } from "@web/core/registry";
import { useService } from "@web/core/utils/hooks";
// Odoo 20: 'useState' ya no existe (Owl fue sustituido por Hoot). El estado
// reactivo se crea con 'proxy', y 'onWillStart' se mantiene.
import { Component, onWillStart, proxy } from "@odoo/owl";

class TRM extends Component {
    static template = "trm_menu";

    setup() {
        this.state = proxy({ trm: 0 });
        this.orm = useService('orm');

        onWillStart(async () => {
            try {
                // Call the model method without arguments
                var trm = await this.orm.call('res.currency', 'get_trm_systray', []);
                this.state.trm = trm;
            } catch (e) {
                console.error('TRM: Error fetching rate', e);
            }
        });
    }

    get trm() {
        return this.state.trm;
    }
}

export const trmItem = { Component: TRM };

registry.category("systray").add("TRM", trmItem, { sequence: 1 });
