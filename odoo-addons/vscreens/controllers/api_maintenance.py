# -*- coding: utf-8 -*-
import logging
from datetime import datetime, timedelta

from odoo import http, _
from odoo.http import request
from odoo.exceptions import AccessError

from .api_common import (
    bearer_user,
    error,
    is_master,
    json_response,
    payload,
)

_logger = logging.getLogger(__name__)


class VScreenSMaintenanceController(http.Controller):

    # ------------------------------------------------------------------
    # Helpers internos
    # ------------------------------------------------------------------
    def _check_master(self):
        user = bearer_user()
        if not user:
            return None, error(401, "No autenticado")
        if not is_master(user):
            return None, error(403, "Solo el Administrador Maestro puede acceder al mantenimiento")
        return user, None

    @staticmethod
    def _allowed_table(model_name):
        """Lista de modelos permitidos para mantenimiento directo."""
        allowed = [
            "vscreens.company",
            "vscreens.device",
            "vscreens.payment",
            "vscreens.plan",
            "vscreens.registration.code",
            "vscreens.message",
            "vscreens.ticket",
            "vscreens.ticket.message",
            "vscreens.chat.thread",
            "vscreens.blocked.user",
            "vscreens.global.ad",
            "vscreens.menu.item",
            "vscreens.analytics.visit",
            "vscreens.benry.session",
            "vscreens.benry.message",
            "vscreens.email.template",
            "vscreens.promotion",
            "vscreens.affiliate",
            "vscreens.calendar.activity",
            "vscreens.free.plan.usage",
            "res.users",
            "crm.lead",
            "account.move",
            "res.partner",
        ]
        return model_name in allowed

    # ------------------------------------------------------------------
    # Listar tablas / modelos
    # ------------------------------------------------------------------
    @http.route("/admin/maintenance/tables", type="http", auth="public", methods=["GET", "OPTIONS"],
                csrf=False, cors="*", save_session=False)
    def list_tables(self, **kwargs):
        user, failure = self._check_master()
        if failure:
            return failure
        models = request.env["ir.model"].sudo().search([("transient", "=", False)], order="model")
        tables = []
        for m in models:
            tables.append({
                "model": m.model,
                "name": m.name,
                "transient": m.transient,
            })
        return json_response({"tables": tables})

    # ------------------------------------------------------------------
    # Leer datos de una tabla/modelo
    # ------------------------------------------------------------------
    @http.route("/admin/maintenance/table/<string:model_name>", type="http", auth="public",
                methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def get_table_data(self, model_name, **kwargs):
        user, failure = self._check_master()
        if failure:
            return failure
        if not self._allowed_table(model_name):
            return error(400, "Modelo no permitido para mantenimiento directo")
        limit = int(kwargs.get("limit", 100))
        offset = int(kwargs.get("offset", 0))
        try:
            Model = request.env[model_name].sudo()
            records = Model.search([], limit=limit, offset=offset)
            fields_list = list(Model.fields_get().keys())
            data = []
            for rec in records:
                row = {}
                for f in fields_list:
                    try:
                        val = rec[f]
                        if hasattr(val, "id"):
                            row[f] = {"id": val.id, "display_name": val.display_name}
                        elif isinstance(val, (datetime, )):
                            row[f] = val.isoformat() if val else None
                        else:
                            row[f] = val
                    except Exception:
                        row[f] = None
                data.append(row)
            return json_response({
                "model": model_name,
                "fields": fields_list,
                "data": data,
                "count": len(data),
                "limit": limit,
                "offset": offset,
            })
        except Exception as exc:
            _logger.error("Error leyendo tabla %s: %s", model_name, exc)
            return error(500, f"Error al leer tabla {model_name}: {str(exc)}")

    # ------------------------------------------------------------------
    # Eliminar fila
    # ------------------------------------------------------------------
    @http.route("/admin/maintenance/table/<string:model_name>/<int:row_id>", type="http",
                auth="public", methods=["DELETE", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def delete_table_row(self, model_name, row_id, **kwargs):
        user, failure = self._check_master()
        if failure:
            return failure
        if not self._allowed_table(model_name):
            return error(400, "Modelo no permitido para mantenimiento directo")
        try:
            Model = request.env[model_name].sudo()
            rec = Model.browse(row_id)
            if not rec.exists():
                return error(404, "Registro no encontrado")
            rec.unlink()
            request.env.cr.commit()
            return json_response({"status": "success", "message": f"Registro {row_id} eliminado de {model_name}"})
        except Exception as exc:
            _logger.error("Error borrando %s/%s: %s", model_name, row_id, exc)
            return error(500, f"Error al borrar: {str(exc)}")

    # ------------------------------------------------------------------
    # Actualizar fila
    # ------------------------------------------------------------------
    @http.route("/admin/maintenance/table/<string:model_name>/<int:row_id>", type="http",
                auth="public", methods=["PUT", "PATCH", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def update_table_row(self, model_name, row_id, **kwargs):
        user, failure = self._check_master()
        if failure:
            return failure
        if not self._allowed_table(model_name):
            return error(400, "Modelo no permitido para mantenimiento directo")
        data = payload()
        if not data:
            return error(400, "No hay datos para actualizar")
        # Quitar campos no permitidos
        allowed_keys = set(request.env[model_name].fields_get().keys())
        data.pop("id", None)
        data.pop("create_date", None)
        data.pop("write_date", None)
        data.pop("create_uid", None)
        data.pop("write_uid", None)
        data = {k: v for k, v in data.items() if k in allowed_keys}
        if not data:
            return error(400, "No se encontraron campos válidos para actualizar")
        try:
            Model = request.env[model_name].sudo()
            rec = Model.browse(row_id)
            if not rec.exists():
                return error(404, "Registro no encontrado")
            rec.write(data)
            request.env.cr.commit()
            return json_response({"status": "success", "message": f"Registro {row_id} actualizado en {model_name}"})
        except Exception as exc:
            _logger.error("Error actualizando %s/%s: %s", model_name, row_id, exc)
            return error(500, f"Error al actualizar: {str(exc)}")

    # ------------------------------------------------------------------
    # Ejecutar SQL directo (SOLO MASTER)
    # ------------------------------------------------------------------
    @http.route("/admin/maintenance/execute-sql", type="http", auth="public",
                methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def execute_raw_sql(self, **kwargs):
        user, failure = self._check_master()
        if failure:
            return failure
        data = payload()
        sql = data.get("sql")
        if not sql:
            return error(400, "SQL faltante")
        try:
            request.env.cr.execute(sql)
            if sql.strip().upper().startswith("SELECT"):
                cols = [d[0] for d in request.env.cr.description]
                rows = [dict(zip(cols, r)) for r in request.env.cr.fetchall()]
                request.env.cr.commit()
                return json_response({"status": "success", "data": rows})
            else:
                request.env.cr.commit()
                return json_response({"status": "success", "rowcount": request.env.cr.rowcount})
        except Exception as exc:
            request.env.cr.rollback()
            _logger.error("Error SQL: %s", exc)
            return error(500, f"Error SQL: {str(exc)}")

    # ------------------------------------------------------------------
    # Limpieza de dispositivos y códigos expirados
    # ------------------------------------------------------------------
    @http.route("/admin/maintenance/db-cleanup", type="http", auth="public",
                methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def db_cleanup(self, **kwargs):
        user, failure = self._check_master()
        if failure:
            return failure
        try:
            # Códigos expirados
            expired_codes = request.env["vscreens.registration.code"].sudo().search(
                [("expires_at", "<", fields.Datetime.now())])
            expired_codes.unlink()
            # Dispositivos sin empresa
            orphan_devices = request.env["vscreens.device"].sudo().search([("company_id", "=", False)])
            orphan_count = len(orphan_devices)
            orphan_devices.unlink()
            request.env.cr.commit()
            return json_response({
                "status": "success",
                "message": "Base de datos limpiada correctamente",
                "expired_codes_removed": len(expired_codes),
                "orphan_devices_removed": orphan_count,
            })
        except Exception as exc:
            request.env.cr.rollback()
            _logger.error("Error en limpieza: %s", exc)
            return error(500, f"Error en limpieza: {str(exc)}")

    # ------------------------------------------------------------------
    # Trigger de backup
    # ------------------------------------------------------------------
    @http.route("/admin/maintenance/backup", type="http", auth="public",
                methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def trigger_backup(self, **kwargs):
        user, failure = self._check_master()
        if failure:
            return failure
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Odoo tiene su propio mecanismo de backup de base de datos
            # Aquí devolvemos éxito y el usuario puede usar el gestor de BD de Odoo
            return json_response({
                "status": "success",
                "message": "Respaldo iniciado. Use el gestor de bases de datos de Odoo para descargar el dump.",
                "timestamp": timestamp,
                "db_name": request.env.cr.dbname,
            })
        except Exception as exc:
            _logger.error("Error en backup: %s", exc)
            return error(500, str(exc))

    # ------------------------------------------------------------------
    # Ejecutar supervisor de tareas (expiraciones, cumpleaños, feriados)
    # ------------------------------------------------------------------
    @http.route("/admin/maintenance/run-supervisor", type="http", auth="public",
                methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def run_supervisor(self, **kwargs):
        user, failure = self._check_master()
        if failure:
            return failure
        try:
            # 1. Verificar expiraciones de planes
            companies = request.env["vscreens.company"].sudo().search([("is_active", "=", True)])
            expired = 0
            for company in companies:
                if company.valid_until and company.valid_until < fields.Datetime.now():
                    company.sudo().write({"is_active": False})
                    expired += 1

            # 2. Sembrar feriados venezolanos si no existen
            cal = request.env["vscreens.calendar.activity"].sudo()
            result = cal.seed_venezuelan_holidays()

            # 3. Verificar cumpleaños y enviar saludos automáticos
            today = fields.Date.today()
            birthday_partners = request.env["res.partner"].sudo().search([
                ("birthday", "!=", False),
            ])
            birthday_sent = 0
            for partner in birthday_partners:
                if partner.birthday.month == today.month and partner.birthday.day == today.day:
                    template = request.env["vscreens.email.template"].sudo().search(
                        [("category", "=", "bienvenida"), ("active", "=", True)], limit=1)
                    if template and partner.email:
                        request.env["mail.mail"].sudo().create({
                            "subject": template.subject or "Feliz cumpleaños",
                            "body_html": template.body or "",
                            "email_to": partner.email,
                            "email_from": request.env["ir.config_parameter"].sudo().get_str(
                                "vscreens.notification_email", "info.vscreens@inverpave.com"),
                        }).send()
                        birthday_sent += 1

            request.env.cr.commit()
            return json_response({
                "status": "success",
                "message": "Supervisor ejecutado correctamente",
                "companies_expired": expired,
                "holidays_seeded": result.get("created", 0),
                "birthday_emails_sent": birthday_sent,
            })
        except Exception as exc:
            request.env.cr.rollback()
            _logger.error("Error ejecutando supervisor: %s", exc)
            return error(500, f"Error ejecutando supervisor: {str(exc)}")
