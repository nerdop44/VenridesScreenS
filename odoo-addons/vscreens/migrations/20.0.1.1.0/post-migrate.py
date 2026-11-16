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


def _safe_create(env, model, vals):
    """Crea un registro sin abortar la migración completa si un dato es inválido."""
    try:
        with env.cr.savepoint():
            return env[model].create(vals)
    except Exception as error:  # noqa: BLE001 - la migración no debe romperse
        _logger.warning("VScreenS migración: no se pudo crear %s %s (%s)", model, vals, error)
        return env[model]


def _as_list(value):
    return value if isinstance(value, list) else []


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def migrate(cr, version):
    if not version:
        return
    env = api.Environment(cr, SUPERUSER_ID, {})
    company_model = env["vscreens.company"]

    for company in company_model.search([]):
        # --- Notificaciones: el JSON pasa a campos booleanos editables ---
        settings = _as_dict(company.auto_notification_settings)
        notification_vals = {
            "notification_welcome": bool(settings.get("welcome", True)),
            "notification_billing": bool(settings.get("billing", True)),
            "notification_expiry_reminders": bool(settings.get("expiry_reminders", True)),
            "notification_birthday_greetings": bool(settings.get("birthday_greetings", True)),
            "notification_holiday_greetings": bool(settings.get("holiday_greetings", True)),
        }

        # --- Playlist ---
        if not company.playlist_items:
            sequence = 10
            for entry in _as_list(company.video_playlist):
                if isinstance(entry, str):
                    url, title = entry, entry
                elif isinstance(entry, dict):
                    url = entry.get("url") or entry.get("youtube_id")
                    title = entry.get("title") or url
                else:
                    continue
                if not url:
                    continue
                _safe_create(env, "vscreens.playlist.item", {
                    "company_id": company.id,
                    "sequence": sequence,
                    "title": title,
                    "url": url,
                })
                sequence += 10

        # --- Videos programados ---
        if not company.scheduled_video_items:
            sequence = 10
            for entry in _as_list(company.scheduled_videos):
                if not isinstance(entry, dict):
                    continue
                url = entry.get("url")
                if not url or not entry.get("start"):
                    continue
                _safe_create(env, "vscreens.scheduled.video.item", {
                    "company_id": company.id,
                    "sequence": sequence,
                    "title": entry.get("title") or url,
                    "url": url,
                    "start_datetime": entry.get("start"),
                    "end_datetime": entry.get("end") or False,
                    "duration": entry.get("duration") or 300,
                })
                sequence += 10

        # --- Barra lateral ---
        if not company.sidebar_items:
            sequence = 10
            for entry in _as_list(company.sidebar_content):
                if not isinstance(entry, dict):
                    continue
                value = entry.get("value") or entry.get("text")
                if not value:
                    continue
                _safe_create(env, "vscreens.sidebar.item", {
                    "company_id": company.id,
                    "sequence": sequence,
                    "label": entry.get("label") or value[:40],
                    "value": value,
                    "icon": entry.get("icon") or "fa-tv",
                    "color": entry.get("color") or "#ffffff",
                })
                sequence += 10

        # --- Barra inferior (mensajes del ticker) ---
        if not company.bottom_bar_items:
            data = _as_dict(company.bottom_bar_content)
            messages = _as_list(data.get("messages"))
            if not messages and data.get("static"):
                messages = [data["static"]]
            sequence = 10
            for message in messages:
                text = message if isinstance(message, str) else str(message)
                if not text.strip():
                    continue
                _safe_create(env, "vscreens.bottom.bar.item", {
                    "company_id": company.id,
                    "sequence": sequence,
                    "label": text[:40],
                    "value": text,
                    "color": data.get("color") or "#c8ff00",
                })
                sequence += 10

        # --- Ajustes de diseño ---
        if not company.design_settings_id:
            data = _as_dict(company.design_settings)
            design_vals = {
                "company_id": company.id,
                "title_font": data.get("name_font") or "inherit",
                "title_color": data.get("name_color") or "#ffffff",
                "title_size": data.get("name_size") or "1.2rem",
                "title_weight": data.get("name_weight") or "bold",
                "sidebar_width": int(data.get("sidebar_width") or 22),
                "sidebar_effect": data.get("sidebar_effect") or "none",
                "sidebar_bg": data.get("sidebar_bg") or "#1e293b",
                "sidebar_text": data.get("sidebar_text") or "#ffffff",
                "bottom_bar_bg": data.get("bottom_bar_bg") or "#0a0e1a",
                "bottom_bar_text": data.get("bottom_bar_text") or "#ffffff",
                "show_bcv": bool(data.get("show_bcv", True)),
                "bcv_color": data.get("bcv_color") or "#10b981",
                "bcv_font": data.get("bcv_font") or "inherit",
            }
            _safe_create(env, "vscreens.design.settings", design_vals)

        company.write(notification_vals)

    _logger.info("VScreenS migración: configuración visual sincronizada")
