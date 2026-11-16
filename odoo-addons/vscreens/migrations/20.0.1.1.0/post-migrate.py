# -*- coding: utf-8 -*-
"""Migra la configuración JSON histórica a los controles visuales.

Las empresas creadas con la versión anterior guardaban playlist, barra
lateral, barra inferior y diseño directamente en campos JSON. A partir de
esta versión esos datos se editan con listas visuales (One2many), por lo que
es necesario crear los registros equivalentes para que el cliente vea su
configuración actual al abrir la empresa.
"""

import logging

from odoo import SUPERUSER_ID, api

_logger = logging.getLogger(__name__)


def migrate(cr, version):
    if not version:
        return
    env = api.Environment(cr, SUPERUSER_ID, {})
    company_model = env["vscreens.company"]

    for company in company_model.search([]):
        settings = company.auto_notification_settings
        if not isinstance(settings, dict):
            settings = {}
        company.write({
            "notification_welcome": bool(settings.get("welcome", True)),
            "notification_billing": bool(settings.get("billing", True)),
            "notification_expiry_reminders": bool(settings.get("expiry_reminders", True)),
            "notification_birthday_greetings": bool(settings.get("birthday_greetings", True)),
            "notification_holiday_greetings": bool(settings.get("holiday_greetings", True)),
        })

    created = company_model.search([])._hydrate_visuals_from_json()
    _logger.info("VScreenS migración: %s registros visuales creados", created)
