# -*- coding: utf-8 -*-
import logging

_logger = logging.getLogger(__name__)


def post_init_hook(cr, registry):
    """Se ejecuta después de instalar el módulo vscreens.
    Crea las tareas programadas (crons) de mantenimiento."""
    from odoo.api import Environment
    env = Environment(cr, 1, {})

    IrCron = env["ir.cron"].sudo()
    IrModel = env["ir.model"].sudo()

    # Asegurar registros ir.model
    model_company = IrModel.search([("model", "=", "vscreens.company")], limit=1)
    if not model_company:
        model_company = IrModel.create({"model": "vscreens.company"})

    model_partner = IrModel.search([("model", "=", "res.partner")], limit=1)
    if not model_partner:
        model_partner = IrModel.create({"model": "res.partner"})

    model_calendar = IrModel.search([("model", "=", "vscreens.calendar.activity")], limit=1)
    if not model_calendar:
        model_calendar = IrModel.create({"model": "vscreens.calendar.activity"})

    root_user = env.ref("base.user_root", raise_if_not_found=False)

    def _create_or_update_cron(xml_id, name, model_id, code, interval_number, interval_type, active=True):
        cron = IrCron.search([("name", "=", name)], limit=1)
        vals = {
            "name": name,
            "model_id": model_id.id,
            "state": "code",
            "code": code,
            "interval_number": interval_number,
            "interval_type": interval_type,
            "numbercall": -1,
            "doall": False,
            "active": active,
        }
        if root_user:
            vals["user_id"] = root_user.id
        if cron:
            cron.sudo().write(vals)
        else:
            IrCron.sudo().create(vals)

    _create_or_update_cron(
        "cron_check_plan_expiration",
        "VScreenS: Verificar expiración de planes",
        model_company,
        "model._cron_check_plan_expiration()",
        1, "days",
    )
    _create_or_update_cron(
        "cron_send_birthday_greetings",
        "VScreenS: Enviar saludos de cumpleaños",
        model_partner,
        "model._cron_send_birthday_greetings()",
        1, "days",
    )
    _create_or_update_cron(
        "cron_seed_venezuelan_holidays",
        "VScreenS: Sembrar feriados venezolanos",
        model_calendar,
        "model.seed_venezuelan_holidays()",
        1, "months",
    )

    _logger.info("Crons de VScreenS creados/actualizados correctamente")
