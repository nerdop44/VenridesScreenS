import logging

_logger = logging.getLogger(__name__)


def migrate(cr, version):
    """Rellenar `amount_usd` de los parciales de MONEDA UNICA que quedaron en 0.

    Contexto (v307): `account_dual_currency.reconcile()` leia los parciales de
    `super().reconcile()`, pero en Odoo 20 ese metodo devuelve `None` en lugar de
    un diccionario. El `or {}` normalizaba el fallo y `results.get('partials')`
    devolvia siempre un recordset vacio, por lo que el reparto secuencial de
    `amount_usd` nunca se ejecutaba y TODOS los parciales quedaban en 0.

    Esta migracion solo rescata los casos **inequivocos**: parciales cuyos dos
    lados estan en la misma moneda, donde `amount_usd` es necesariamente igual a
    `amount`. Los parciales entre monedas distintas (USD/VES) NO se tocan: su
    valor depende de la tasa del asiento y deben revisarse a mano.
    """
    if not version:
        return

    _logger.info("Pachacutec: v20.0.2.1.1 - Rellenando amount_usd de parciales de moneda unica...")

    # `account.partial.reconcile.company_currency_id` NO es una columna fisica
    # (es un campo calculado), asi que el filtro se hace solo con las columnas
    # reales `debit_currency_id` / `credit_currency_id`. Se exigen ambas
    # informadas: si alguna falta, el par esta en moneda de compania y el caso
    # es ambiguo, asi que se omite antes que suponer.
    cr.execute("""
        SELECT p.id, p.amount, p.debit_currency_id
        FROM account_partial_reconcile p
        WHERE p.amount_usd = 0
          AND p.amount <> 0
          AND p.debit_currency_id IS NOT NULL
          AND p.credit_currency_id IS NOT NULL
          AND p.debit_currency_id = p.credit_currency_id
        ORDER BY p.id
    """)
    rows = cr.fetchall()

    if not rows:
        _logger.info("Pachacutec: v20.0.2.1.1 - No hay parciales de moneda unica con amount_usd = 0. Nada que hacer.")
        return

    for partial_id, amount, currency_id in rows:
        _logger.info(
            "Pachacutec: v20.0.2.1.1 - parcial %s: amount=%s -> amount_usd=%s (moneda %s)",
            partial_id, amount, amount, currency_id,
        )
        cr.execute(
            "UPDATE account_partial_reconcile SET amount_usd = amount WHERE id = %s",
            (partial_id,),
        )

    _logger.info(
        "Pachacutec: v20.0.2.1.1 - %s parcial(es) de moneda unica actualizados. "
        "Los de moneda distinta quedan en 0 a proposito, pendientes de revision manual.",
        len(rows),
    )