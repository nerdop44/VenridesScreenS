# -*- coding: utf-8 -*-
import logging

_logger = logging.getLogger(__name__)


def post_init_hook(env):
    """Hook post-instalación compatible con Odoo 20.
    Los crons viven declarativamente en data/cron.xml; aquí solo
    sembramos feriados iniciales si la tabla está vacía."""
    try:
        cal = env["vscreens.calendar.activity"].sudo()
        if not cal.search_count([("is_holiday", "=", True)]):
            cal.seed_venezuelan_holidays()
    except Exception as exc:
        _logger.warning("post_init_hook: no se pudieron sembrar feriados iniciales: %s", exc)
    _logger.info("post_init_hook de VScreenS completado (Odoo 20)")
