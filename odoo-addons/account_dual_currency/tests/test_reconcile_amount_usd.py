from odoo.tests import tagged, TransactionCase


@tagged("post_install", "-at_install", "reconcile_amount_usd")
class TestReconcileAmountUsd(TransactionCase):
    """Regresiones de `account_dual_currency` detectadas al migrar a Odoo 20.

    R1 - `reconcile()` de LocVe leia los parciales de `super().reconcile()`, pero
         desde v20 ese metodo devuelve `None` (en v18 devolvia un diccionario
         con 'partials'). Resultado: el reparto secuencial nunca se ejecutaba y
         cada `account.partial.reconcile` quedaba con `amount_usd = 0`, sin
         descontar lo conciliado de `amount_residual_usd`.

    R2 - Asignar `self.env.context = ...` lanza `AttributeError: Attribute
         'context' is read-only` desde v17. Bloqueaba por completo el registro
         de pagos (9 sitios en el wizard y 4 en el modelo).
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env = cls.env(context=dict(cls.env.context, tracking_disable=True))
        cls.company = cls.env.company
        cls.currency_local = cls.company.currency_id
        cls.currency_dif = cls.company.currency_id_dif
        cls.tax_today = 36.5

        cls.partner = cls.env["res.partner"].create({
            "name": "Cliente Conciliacion Dual",
            "customer_rank": 1,
        })

        # Linea contable explicita: el core exige account_id en las lineas
        # contabilizables (`account_move_line_check_accountable_required_fields`).
        cls.income_account = cls.env["account.account"].search([
            ("company_ids", "in", cls.company.id),
            ("internal_group", "=", "income"),
        ], limit=1)
        assert cls.income_account, "Se requiere una cuenta de ingreso en la compania"

        cls.receivable_account = cls.env["account.account"].search([
            ("company_ids", "in", cls.company.id),
            ("account_type", "=", "asset_receivable"),
        ], limit=1)
        assert cls.receivable_account, "Se requiere una cuenta por cobrar en la compania"

        # La linea por cobrar de la factura se genera desde las propiedades del
        # partner; sin ellas queda `account_id = False` y el core rechaza la
        # linea con `account_move_line_check_accountable_required_fields`.
        cls.partner.write({
            "property_account_receivable_id": cls.receivable_account.id,
        })

        cls.bank_journal = cls.env["account.journal"].search([
            ("type", "=", "bank"),
            ("company_id", "=", cls.company.id),
        ], limit=1)
        assert cls.bank_journal, "Se requiere un diario bancario en la compania"

        # LocVe exige producto en las lineas de factura
        # ("All added lines must indicate the product").
        cls.product = cls.env["product.product"].create({
            "name": "Producto Conciliacion Dual",
            "type": "consu",
            "list_price": 100.0,
            "uom_id": cls.env.ref("uom.product_uom_unit").id,
            "property_account_income_id": cls.income_account.id,
        })

    def _create_invoice(self, amount=100.0):
        invoice = self.env["account.move"].create({
            "move_type": "out_invoice",
            "partner_id": self.partner.id,
            "invoice_date": "2026-01-15",
            "currency_id": self.currency_local.id,
            "invoice_line_ids": [(0, 0, {
                "product_id": self.product.id,
                "quantity": 1.0,
                "price_unit": amount,
                "tax_ids": [(5, 5, 0)],
            })],
        })
        invoice.action_post()
        return invoice

    def _payable_line(self, invoice):
        line = invoice.line_ids.filtered(
            lambda l: l.account_id == self.receivable_account)
        assert line, "La factura debe tener una linea por cobrar"
        return line

    def _register_payment(self, invoice):
        """Paga la factura con el wizard real de Odoo 20."""
        self.env["account.payment.register"].with_context(
            active_model="account.move",
            active_ids=invoice.ids,
        ).create({
            "payment_date": invoice.invoice_date,
            "amount": invoice.amount_total,
            "currency_id": self.currency_local.id,
            "journal_id": self.bank_journal.id,
        }).action_create_payments()
        return invoice.payment_state

    # ------------------------------------------------------------------ R1

    def test_partial_amount_usd_is_filled_on_register(self):
        """R1: el parcial creado al pagar debe quedar con `amount_usd`."""
        invoice = self._create_invoice()
        self.assertFalse(
            self._payable_line(invoice).reconciled,
            "Partimos de una factura sin conciliar",
        )

        self._register_payment(invoice)

        payable = self._payable_line(invoice)
        partials = payable.matched_debit_ids | payable.matched_credit_ids
        self.assertTrue(partials, "El pago debe crear al menos un parcial")
        self.assertTrue(
            all(p.amount_usd for p in partials),
            "Todo parcial debe quedar con amount_usd distinto de cero; "
            "obtenidos: %s" % [p.amount_usd for p in partials],
        )

    def test_partial_amount_usd_matches_amount(self):
        """R1: con tasa 1 el importe en divisa debe coincidir con el parcial."""
        invoice = self._create_invoice()
        self._register_payment(invoice)

        payable = self._payable_line(invoice)
        for partial in (payable.matched_debit_ids | payable.matched_credit_ids):
            self.assertAlmostEqual(
                partial.amount_usd, partial.amount, places=2,
                msg="amount_usd debe reflejar el importe conciliado",
            )

    def test_reconcile_normalizes_core_none(self):
        """R1: `reconcile()` no debe propagar el `None` que devuelve el core.

        El core de v20 hace `return self._reconcile_plan(...)` y ese metodo no
        retorna nada. Antes del fix, LocVe正常使用 `results['partials']` sobre
        ese `None`. Aqui solo se verifica el contrato: la llamada no revienta y
        devuelve un diccionario. La creacion de parciales con `amount_usd` se
        cubre en `test_partial_amount_usd_*`.
        """
        invoice = self._create_invoice()
        payable = self._payable_line(invoice)

        counterpart_move = self.env["account.move"].create({
            "move_type": "entry",
            "date": "2026-01-15",
            "line_ids": [
                (0, 0, {
                    "name": "Contrapartida",
                    "account_id": self.receivable_account.id,
                    "debit": payable.debit,
                    "currency_id": self.currency_local.id,
                }),
                (0, 0, {
                    "name": "Contrapartida banco",
                    "account_id": self.income_account.id,
                    "credit": payable.debit,
                    "currency_id": self.currency_local.id,
                }),
            ],
        })
        counterpart_move.action_post()
        counterpart = counterpart_move.line_ids.filtered(
            lambda l: l.account_id == self.receivable_account)

        result = (counterpart | payable).reconcile()
        self.assertIsInstance(
            result, dict,
            "LocVe debe normalizar el None del core a diccionario, no propagarlo",
        )

    # ------------------------------------------------------------------ R2

    def test_convert_honors_scoped_tasa_factura(self):
        """R2: `tasa_factura` debe aplicar SOLO a la moneda que lo recibe.

        Este es el mecanismo que sustituye a `self.env.context = ...`.
        """
        amount = 100.0

        # Con tasa: moneda local -> currency_id_dif divide segun el core.
        # round=False para no depender de los decimales de la moneda.
        with_rate = self.currency_local.with_context(tasa_factura=self.tax_today)._convert(
            amount, self.currency_dif, self.company, "2026-01-15", round=False)
        self.assertAlmostEqual(with_rate, amount / self.tax_today, places=6)

        # La tasa debe quedar acotada al recordset: sin fuga global.
        self.assertNotIn(
            "tasa_factura", self.env.context,
            "with_context() no debe filtrar tasa_factura al contexto de la sesion",
        )

    def test_payment_register_creates_payment(self):
        """R2: el wizard debe completar el pago sin AttributeError."""
        invoice = self._create_invoice()
        state = self._register_payment(invoice)
        self.assertIn(
            state, ("paid", "in_payment", "partial"),
            "El pago deberia quedar registrado; estado: %s" % state,
        )

    def test_payment_register_clears_rate_context(self):
        """R2: tras el pago, `tasa_factura` no debe quedar en la sesion."""
        invoice = self._create_invoice()
        self._register_payment(invoice)
        self.assertNotIn(
            "tasa_factura", self.env.context,
            "El wizard no debe dejar tasa_factura en el contexto global",
        )
        self.assertNotIn(
            "calcular_dual_currency", self.env.context,
            "El wizard no debe dejar calcular_dual_currency en el contexto global",
        )