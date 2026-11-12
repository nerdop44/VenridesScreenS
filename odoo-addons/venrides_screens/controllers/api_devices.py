from odoo import fields, http
from odoo.http import request

from .api_common import (
    bearer_user,
    can_access_company,
    company_or_404,
    device_or_404,
    error,
    is_master,
    json_response,
    payload,
    role_of,
)


class VenridesDeviceController(http.Controller):

    @http.route("/devices/<string:device_uuid>/config", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def device_config(self, device_uuid, **kwargs):
        device = device_or_404(device_uuid)
        if not device:
            return error(404, "Dispositivo no registrado")
        if not device.company_id:
            return error(404, "Dispositivo no vinculado a una empresa")
        device.register_ping(request.httprequest.headers.get("X-Forwarded-For", request.httprequest.remote_addr))
        return json_response(device.company_id.device_config(device))

    @http.route("/devices/validate-code", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def validate_code(self, **kwargs):
        code = request.httprequest.args.get("code") or payload().get("code")
        device_uuid = request.httprequest.args.get("device_uuid") or payload().get("device_uuid")
        if not code or not device_uuid:
            return error(400, "Código y device_uuid son obligatorios")
        ok, result = request.env["venrides.registration.code"].sudo().validate_for_device(
            code, device_uuid, request.httprequest.headers.get("X-Forwarded-For", request.httprequest.remote_addr)
        )
        if not ok:
            return error(result.get("status", 400), result.get("detail", "Error"))
        return json_response(result)

    @http.route("/devices/generate-code", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def generate_code(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        company_id = request.httprequest.args.get("company_id") or payload().get("company_id")
        company = company_or_404(company_id) if company_id else company_or_404(user.venrides_company_id.id if user.venrides_company_id else 0)
        if not company:
            return error(404, "Empresa no encontrada")
        if not can_access_company(user, company):
            return error(403, "No autorizado")
        result = request.env["venrides.registration.code"].sudo().generate_for_company(company)
        return json_response(result)

    @http.route("/devices/<string:device_uuid>/rename", type="http", auth="public", methods=["PATCH", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def rename_device(self, device_uuid, **kwargs):
        user = bearer_user()
        device = device_or_404(device_uuid)
        if not user or not device:
            return error(404, "Dispositivo no encontrado")
        if not can_access_company(user, device.company_id):
            return error(403, "No autorizado")
        data = payload()
        name = (data.get("name") or "").strip()
        if not name:
            return error(400, "Nombre requerido")
        device.sudo().write({"name": name})
        return json_response({"status": "success", "name": device.name})

    @http.route("/diag/ping", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def send_ping(self, **kwargs):
        user = bearer_user()
        device_uuid = request.httprequest.args.get("uuid") or payload().get("uuid")
        device = device_or_404(device_uuid) if device_uuid else None
        if not user:
            return error(401, "No autenticado")
        if not device:
            return error(404, "Dispositivo no encontrado")
        if not can_access_company(user, device.company_id):
            return error(403, "No tiene permiso sobre este dispositivo")
        device.action_ping()
        return json_response({"status": "ping_sent", "uuid": device.uuid})

    @http.route("/admin/devices/", type="http", auth="public", methods=["GET", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def admin_devices(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        if request.httprequest.method == "GET":
            domain = [] if is_master(user) else [("company_id", "=", user.venrides_company_id.id)]
            devices = request.env["venrides.device"].sudo().search(domain)
            return json_response([device.api_dict() for device in devices])
        if not is_master(user):
            return error(403, "No autorizado")
        data = payload()
        device_uuid = (data.get("uuid") or "").strip()
        company = company_or_404(data.get("company_id"))
        if not device_uuid or not company:
            return error(400, "UUID y company_id son requeridos")
        device = device_or_404(device_uuid)
        if device:
            device.sudo().write({"company_id": company.id, "name": data.get("name") or device.name})
        else:
            device = request.env["venrides.device"].sudo().create({
                "uuid": device_uuid,
                "company_id": company.id,
                "name": data.get("name") or f"TV-{device_uuid[:8]}",
            })
        return json_response({"message": "Dispositivo vinculado correctamente", "uuid": device.uuid})

    @http.route("/admin/devices/<string:device_uuid>", type="http", auth="public", methods=["PATCH", "POST", "DELETE", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def admin_device_detail(self, device_uuid, **kwargs):
        user = bearer_user()
        device = device_or_404(device_uuid)
        if not user or not device:
            return error(404, "Dispositivo no encontrado")
        if not can_access_company(user, device.company_id):
            return error(403, "No tiene permiso para editar este dispositivo")
        if request.httprequest.method == "DELETE":
            if not (is_master(user) or role_of(user) == "admin_empresa"):
                return error(403, "No autorizado")
            device.sudo().unlink()
            return json_response({"message": "Dispositivo eliminado correctamente"})
        data = payload()
        name = (data.get("name") or "").strip()
        if not name:
            return error(400, "Nombre requerido")
        device.sudo().write({"name": name})
        return json_response({"message": "Dispositivo actualizado correctamente"})

    @http.route("/admin/devices/<string:device_uuid>/status", type="http", auth="public", methods=["PATCH", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def admin_device_status(self, device_uuid, **kwargs):
        user = bearer_user()
        device = device_or_404(device_uuid)
        if not user or not device:
            return error(404, "Dispositivo no encontrado")
        if not can_access_company(user, device.company_id):
            return error(403, "No autorizado")
        raw = request.httprequest.args.get("is_active", "true").lower()
        is_active = raw in ("1", "true", "yes")
        device.sudo().write({"is_active": is_active})
        return json_response({"message": "Estatus actualizado", "is_active": is_active})

    @http.route("/admin/debug/stats", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def debug_stats(self, **kwargs):
        user = bearer_user()
        if not user or not is_master(user):
            return error(403, "No autorizado")
        devices = request.env["venrides.device"].sudo().search([])
        companies = request.env["venrides.company"].sudo().search([])
        return json_response({
            "total_devices": len(devices),
            "total_companies": len(companies),
            "devices": [{"id": d.id, "uuid": d.uuid, "name": d.name, "company_id": d.company_id.id} for d in devices],
            "companies": [{"id": c.id, "name": c.name} for c in companies],
        })

    @http.route("/diag/status", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def diag_status(self, **kwargs):
        Company = request.env["venrides.company"].sudo()
        User = request.env["res.users"].sudo()
        Device = request.env["venrides.device"].sudo()
        return json_response({
            "status": "healthy",
            "db": {
                "companies": Company.search_count([]),
                "users": User.search_count([]),
                "devices": Device.search_count([]),
            },
        })

    @http.route("/support/unread-count", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def unread_count(self, **kwargs):
        user = bearer_user()
        if not user:
            return json_response({"count": 0})
        domain = [("status", "in", ("open", "in_progress"))]
        if not is_master(user):
            domain.append(("user_id", "=", user.id))
        count = request.env["venrides.ticket"].sudo().search_count(domain)
        return json_response({"count": count})
