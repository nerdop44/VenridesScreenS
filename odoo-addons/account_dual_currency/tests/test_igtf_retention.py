from odoo.tests import tagged, TransactionCase


@tagged("post_install", "-at_install", "igtf_retention")
class TestIgftRetention(TransactionCase):
    """Regresiones del wizard de retencion IGTF (`generar.igtf.wizard`).

    I1 - El boton "Generar IGTF" ofrecia `default_tax_today =
         currency_id_dif.inverse_rate`. `tax_today` significa "moneda alterna
         por 1 unidad de base" (ver `_compute_tax_today`) e `inverse_rate` del
         core significa justo lo contrario. Con la base en USD y la alterna VES
         el wizard ofrecia 0,0012 en vez de 857,89.

    I2 - El asiento de retencion intercambiaba los papeles de `debit`/`credit`
         (moneda de compania) y `amount_currency` (moneda de la linea). Una
         retencion de 34,80 USD se contabilizaba como 29.854,49 USD.

    I3 - `get_odoo_rate` (dentro de `_prepare_reconciliation_single_partial`)
         devolvia `1 / tax_today`. Con la base al reves el `partial_amount`
         salia 0 y los 1.160 USD enteros de la factura se contabilizaban como
         diferencia de cambio y se conciliaban contra ella, dejandola PAGADA.

    I4 - `amount_residual_usd` depende de `matched_debit_ids` /
         `matched_credit_ids` pero no de `amount_usd`, que es lo que escribe
         `reconcile()`. El residual almacenado quedaba obsoleto.

    La tasa no se fija a un valor concreto: `account.move.tax_today` se
    recomputa desde la TRM publicada y su valor por defecto no es estable entre
    bases de datos. Lo que se comprueba es la ORIENTACION (mayor que 1 con la
    base en USD y la alterna VES) y la coherencia interna, que es lo que
    rompian estas regresiones.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env = cls.env(context=dict(cls.env.context, tracking_disable=True))
        cls.company = cls.env.company
        cls.currency_base = cls.company.currency_id
        cls.currency_dif = cls.company.currency_id_dif

        cls.partner = cls.env["res.partner"].create({
            "name": "Cliente Retencion IGTF",
            "customer_rank": 1,
        })

        cls.income_account = cls.env["account.account"].search([
            ("company_ids", "in", cls.company.id),
            ("internal_group", "=", "income"),
        ], limit=1)
        assert cls.income_account, "Se requiere una cuenta de ingreso"

        cls.receivable_account = cls.env["account.account"].search([
            ("company_ids", "in", cls.company.id),
            ("account_type", "=", "asset_receivable"),
        ], limit=1)
        assert cls.receivable_account, "Se requiere una cuenta por cobrar"

        cls.igtf_account = cls.env["account.account"].search([
            ("company_ids", "in", cls.company.id),
            ("account_type", "=", "liability_current"),
            ("id", "!=", cls.receivable_account.id),
        ], limit=1)
        if not cls.igtf_account:
            cls.igtf_account = cls.env["account.account"].create({
                "name": "IGTF retenido",
                "code": "2.1.99.98",
                "account_type": "liability_current",
                "company_ids": [(4, cls.company.id)],
            })

        cls.journal = cls.env["account.journal"].search([
            ("type", "=", "general"),
            ("company_id", "=", cls.company.id),
        ], limit=1)
        assert cls.journal, "Se requiere un diario general"

        cls.partner.write({
            "property_account_receivable_id": cls.receivable_account.id,
        })

        cls.product = cls.env["product.product"].create({
            "name": "Producto Retencion IGTF",
            "type": "consu",
            "list_price": 100.0,
            "uom_id": cls.env.ref("uom.product_uom_unit").id,
            "property_account_income_id": cls.income_account.id,
        })

    def _create_invoice(self, amount=1000.0):
        invoice = self.env["account.move"].create({
            "move_type": "out_invoice",
            "partner_id": self.partner.id,
            "invoice_date": "2026-01-15",
            "currency_id": self.currency_base.id,
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

    def _apply_igtf(self, invoice):
        """Ejecuta el flujo real del boton: defaults, wizard y `generar_retencion`."""
        context = invoice.generar_retencion_igtf()["context"]
        wizard = self.env["generar.igtf.wizard"].with_context(**context).create({
            "invoice_id": context["default_invoice_id"],
            "journal_id": self.journal.id,
            "account_id": self.igtf_account.id,
        })
        wizard.compute_igtf_amount()
        wizard.generar_retencion()
        return context, wizard, invoice.move_igtf_id

    # ------------------------------------------------------------------ I1

    def test_button_offers_tax_today_not_its_inverse(self):
        """I1: `default_tax_today` debe ser la tasa de la factura, no su inversa."""
        invoice = self._create_invoice()
        context = invoice.generar_retencion_igtf()["context"]
        tasa = context["default_tax_today"]

        self.assertAlmostEqual(
            tasa, invoice.tax_today, places=2,
            msg="El boton debe ofrecer la tasa de la factura (%s); ofrecio %s" % (
                invoice.tax_today, tasa),
        )
        self.assertNotAlmostEqual(
            tasa, 1.0 / invoice.tax_today, places=2,
            msg="El boton no debe ofrecer el inverso de la tasa (%s)" % (
                1.0 / invoice.tax_today),
        )

    def test_tax_today_orientation_is_alternate_per_base(self):
        """I1: con la base distinta de la alterna, la tasa debe ser > 1.

        `tax_today` es "moneda alterna por 1 unidad de base", luego con la
        compania en USD y la alterna VES vale ~858. El inverso (~0,0012) es lo
        que ofrecia el boton.
        """
        if self.currency_base == self.currency_dif:
            self.skipTest("La base y la alterna son la misma moneda")
        invoice = self._create_invoice()
        self.assertGreater(
            invoice.tax_today, 1.0,
            "`tax_today` debe ser moneda alterna por unidad de base",
        )
        context = invoice.generar_retencion_igtf()["context"]
        self.assertGreater(context["default_tax_today"], 1.0)

    def test_igtf_amount_in_bolivares_uses_the_rate(self):
        """I1: el IGTF en bolivares debe ser el IGTF en divisa por la tasa."""
        invoice = self._create_invoice()
        context = invoice.generar_retencion_igtf()["context"]

        wizard = self.env["generar.igtf.wizard"].with_context(**context).create({
            "invoice_id": context["default_invoice_id"],
            "journal_id": self.journal.id,
            "account_id": self.igtf_account.id,
        })
        wizard.compute_igtf_amount()

        esperado_usd = context["default_amount"] * wizard.igtf_porcentage / 100.0
        esperado_bs = esperado_usd * context["default_tax_today"]
        self.assertAlmostEqual(wizard.igtf_amount, esperado_usd, places=2)
        self.assertAlmostEqual(
            wizard.igtf_amount_bs, esperado_bs, places=2,
            msg="El IGTF en bolivares salio %s; esperado %s" % (
                wizard.igtf_amount_bs, esperado_bs),
        )

    # ------------------------------------------------------------------ I2

    def test_retention_entry_respects_odoo_currency_convention(self):
        """I2: `debit`/`credit` en moneda de compania, `amount_currency` en la
        moneda de la linea. Antes se intercambiaban y el IGTF en divisa
        contabilizaba como su equivalente en bolivares.
        """
        invoice = self._create_invoice()
        _context, wizard, move = self._apply_igtf(invoice)

        line = move.line_ids.filtered(
            lambda l: l.account_id == self.receivable_account)
        self.assertEqual(len(line), 1, "El asiento debe tener una linea por cobrar")

        # El importe de la linea en MONEDA DE COMPANIA es el IGTF en divisa
        # cuando la divisa es la moneda de compania.
        if self.currency_dif == self.company.currency_id:
            esperado_compania = wizard.igtf_amount_bs
        else:
            esperado_compania = wizard.igtf_amount
        self.assertAlmostEqual(
            abs(line.balance), esperado_compania, places=2,
            msg="`debit`/`credit` debe valer el IGTF en moneda de compania "
                "(%s); la linea vale %s" % (esperado_compania, line.balance),
        )

        # Y en `amount_currency` va el IGTF en la moneda de la linea.
        self.assertEqual(line.currency_id, self.currency_dif)
        self.assertAlmostEqual(
            abs(line.amount_currency), wizard.igtf_amount_bs, places=2,
            msg="`amount_currency` debe valer el IGTF en la moneda de la linea",
        )

    def test_retention_entry_balances(self):
        """I2: el asiento de retencion debe cuadrar en moneda de compania."""
        invoice = self._create_invoice()
        _context, _wizard, move = self._apply_igtf(invoice)

        self.assertAlmostEqual(
            sum(move.line_ids.mapped("debit")),
            sum(move.line_ids.mapped("credit")),
            places=2,
            msg="El asiento de retencion no cuadra",
        )

    # ------------------------------------------------------------------ I3

    def test_reconcile_cross_currency_partial_has_amount(self):
        """I3: conciliar moneda de compania contra alterna debe dar `amount > 0`.

        Con `get_odoo_rate` invertido el `partial_amount` salia 0 y la factura
        entera se iba como diferencia de cambio.
        """
        invoice = self._create_invoice()
        payable = self._payable_line(invoice)
        tasa = invoice.tax_today

        # Contrapartida en la MONEDA ALTERNA por el mismo importe en divisa.
        # Sin `partner_id`: con partner, el inverso de `reconciled_lines_ids`
        # del core intenta autorreconciliar contra cualquier otra linea abierta
        # de la misma cuenta en la base de datos.
        amount_dif = tasa * payable.debit
        move = self.env["account.move"].create({
            "move_type": "entry",
            "date": "2026-01-15",
            "tax_today": tasa,
            "currency_id_dif": self.currency_dif.id,
            "line_ids": [
                (0, 0, {
                    "name": "Contrapartida divisa",
                    "account_id": self.receivable_account.id,
                    "credit": payable.debit,
                    "amount_currency": -amount_dif,
                    "currency_id": self.currency_dif.id,
                }),
                (0, 0, {
                    "name": "Contrapartida banco",
                    "account_id": self.income_account.id,
                    "debit": payable.debit,
                    "amount_currency": amount_dif,
                    "currency_id": self.currency_dif.id,
                }),
            ],
        })
        move.action_post()
        counterpart = move.line_ids.filtered(
            lambda l: l.account_id == self.receivable_account)

        before = payable.matched_debit_ids | payable.matched_credit_ids
        (counterpart | payable).reconcile()
        new_partials = (payable.matched_debit_ids | payable.matched_credit_ids) - before

        self.assertTrue(
            new_partials, "La conciliacion debe crear al menos un parcial")
        for partial in new_partials:
            self.assertNotEqual(
                partial.amount, 0.0,
                "Un parcial en 0 significa que `get_odoo_rate` esta invertido: "
                "el importe de la factura se ira como diferencia de cambio",
            )
            self.assertAlmostEqual(
                partial.amount, payable.debit, places=2,
                msg="El parcial debe conciliar el importe completo de la linea",
            )

    def test_igtf_does_not_pay_the_invoice(self):
        """I3: una retencion parcial no puede dejar la factura como pagada."""
        invoice = self._create_invoice()
        _context, wizard, _move = self._apply_igtf(invoice)

        self.assertNotEqual(
            invoice.payment_state, "paid",
            "La retencion de %s no puede cerrar una factura de %s" % (
                wizard.igtf_amount, invoice.amount_total),
        )

    def test_igtf_creates_no_exchange_difference_move(self):
        """I3: con la misma tasa que la factura no debe haber diferencia de cambio."""
        invoice = self._create_invoice()
        _context, _wizard, move = self._apply_igtf(invoice)

        exchange_moves = self.env["account.move"].search([
            ("journal_id.type", "=", "general"),
            ("ref", "=", invoice.name),
            ("id", "!=", move.id),
        ])
        self.assertFalse(
            exchange_moves,
            "No debe crearse un asiento de diferencia de cambio para la factura "
            "%s; se crearon: %s" % (invoice.name, exchange_moves.mapped("name")),
        )

    def test_igtf_reconciles_exactly_the_igtf(self):
        """I3: lo conciliado en divisa debe ser exactamente el IGTF."""
        invoice = self._create_invoice()
        payable = self._payable_line(invoice)
        _context, wizard, _move = self._apply_igtf(invoice)

        payable.invalidate_recordset()
        conciliado = sum(
            (payable.matched_debit_ids | payable.matched_credit_ids)
            .filtered(lambda p: p.debit_move_id == payable)
            .mapped("amount_usd")
        )
        self.assertAlmostEqual(
            conciliado, wizard.igtf_amount, places=2,
            msg="Se conciliaron %s en divisa; el IGTF es %s" % (
                conciliado, wizard.igtf_amount),
        )

    # ------------------------------------------------------------------ I4

    def test_residual_usd_is_updated_without_manual_recompute(self):
        """I4: `amount_residual_usd` debe descontar el IGTF sin tocarlo a mano.

        `amount_residual_usd` depende de `matched_*_ids` pero no de `amount_usd`,
        que es lo que escribe `reconcile()`. Antes el valor almacenado quedaba
        con el residual integro.
        """
        invoice = self._create_invoice()
        payable = self._payable_line(invoice)
        residual_antes = payable.amount_residual_usd

        _context, wizard, _move = self._apply_igtf(invoice)

        payable.invalidate_recordset()
        self.assertAlmostEqual(
            payable.amount_residual_usd, residual_antes - wizard.igtf_amount,
            places=2,
            msg="`amount_residual_usd` quedo en %s; se esperaba %s sin "
                "recomputar a mano" % (
                    payable.amount_residual_usd, residual_antes - wizard.igtf_amount),
        )

    def test_partial_amount_usd_is_filled_on_igtf(self):
        """El parcial de la retencion debe quedar con `amount_usd`."""
        invoice = self._create_invoice()
        _context, _wizard, _move = self._apply_igtf(invoice)

        partials = self.env["account.partial.reconcile"].search([
            ("debit_move_id.move_id", "=", invoice.id),
        ])
        self.assertTrue(partials, "La retencion debe crear un parcial")
        for partial in partials:
            self.assertNotEqual(
                partial.amount_usd, 0.0,
                "El parcial de la retencion quedo con amount_usd = 0",
            )
