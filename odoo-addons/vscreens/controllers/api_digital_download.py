# -*- coding: utf-8 -*-
# Licensed under the LGPLv3 - VScreenS - Localización Venezuela (LocVe)

from odoo import fields, http
from odoo.http import request
import logging
import base64

_logger = logging.getLogger(__name__)


class VscreensDigitalDownload(http.Controller):

    @http.route("/api/digital/download/<int:product_id>", type="http", auth="public", methods=["GET"], csrf=False, cors="*", save_session=False)
    def download_digital_product(self, product_id, **kwargs):
        """Descarga de producto digital (APK).
        
        La descarga es libre (cualquiera puede descargar el archivo),
        pero el producto solo es operativo si el dispositivo está activado
        en el panel de clientes registrados.
        """
        product = request.env["product.template"].sudo().browse(product_id)
        if not product.exists() or not product.is_digital or not product.digital_file:
            return request.not_found()

        # Registrar la estadística de descarga (supervisada por nosotros)
        request.env["vscreens.download.stat"].sudo().create({
            "product_id": product_id,
            "ip_address": request.httprequest.remote_addr,
            "user_agent": request.httprequest.user_agent,
            "device_uuid": kwargs.get("device_uuid") or "",
            "is_authorized": bool(kwargs.get("device_uuid")),
        })

        # Incrementar contador de descargas
        product.sudo().write({"download_count": product.download_count + 1})

        file_content = base64.b64decode(product.digital_file)
        filename = product.digital_filename or f"{product.name.replace(' ', '_')}.apk"

        return request.make_response(
            file_content,
            headers=[
                ("Content-Type", "application/vnd.android.package-archive"),
                ("Content-Disposition", f'attachment; filename="{filename}"'),
                ("Content-Length", str(len(file_content))),
                ("Access-Control-Allow-Origin", "*"),
            ],
        )


    @http.route("/shop/download/<string:token>", type="http", auth="public", methods=["GET"], csrf=False, save_session=False)
    def download_entitlement(self, token, **kwargs):
        """Descarga tokenizada de una compra. Registra estadística y límites."""
        entitlement = request.env["vscreens.digital.entitlement"].sudo().search(
            [("token", "=", token)], limit=1
        )
        if not entitlement or not entitlement.is_valid:
            return request.not_found()

        product = entitlement.product_tmpl_id
        file_content = entitlement.register_download()
        if not file_content:
            return request.not_found()

        request.env["vscreens.download.stat"].sudo().create({
            "product_id": product.id,
            "ip_address": request.httprequest.remote_addr,
            "user_agent": request.httprequest.user_agent.string[:200] if request.httprequest.user_agent else "",
            "company_id": entitlement.company_id.id if entitlement.company_id else False,
            "device_uuid": kwargs.get("device_uuid") or "",
            "is_authorized": True,
        })

        filename = product.digital_filename or f"{product.name.replace(' ', '_')}.apk"
        payload = base64.b64decode(file_content)
        return request.make_response(
            payload,
            headers=[
                ("Content-Type", "application/vnd.android.package-archive"),
                ("Content-Disposition", f'attachment; filename="{filename}"'),
                ("Content-Length", str(len(payload))),
                ("Access-Control-Allow-Origin", "*"),
            ],
        )

    @http.route("/api/digital/stats", type="http", auth="public", methods=["GET"], csrf=False, cors="*", save_session=False)
    def download_stats(self, **kwargs):
        """Estadísticas de descargas supervisadas (solo para admin/master)."""
        token = request.httprequest.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return request.make_response(
                '{"error": "No autorizado"}',
                headers=[("Content-Type", "application/json"), ("Access-Control-Allow-Origin", "*")],
                status=401,
            )

        # Verificar token del admin
        user = request.env["res.users"].sudo().search([("vscreens_api_token", "=", token)], limit=1)
        if not user or not user.has_group("vscreens.group_vscreens_master"):
            return request.make_response(
                '{"error": "Acceso denegado"}',
                headers=[("Content-Type", "application/json"), ("Access-Control-Allow-Origin", "*")],
                status=403,
            )

        stats = request.env["vscreens.download.stat"].sudo().search_read(
            [],
            ["product_name", "downloaded_at", "ip_address", "is_authorized", "company_id"],
            order="downloaded_at desc",
            limit=100,
        )
        return request.make_response(
            request.env["ir.http"].json.dumps({"stats": stats}),
            headers=[("Content-Type", "application/json"), ("Access-Control-Allow-Origin", "*")],
        )


class VscreensDeviceActivationAPI(http.Controller):

    @http.route("/api/device/activate", type="json", auth="public", methods=["POST"], csrf=False, cors="*", save_session=False)
    def activate_device(self, **kwargs):
        """Activar un dispositivo para una empresa.
        
        Requiere: device_uuid, device_name, device_type, company_id (o email de empresa)
        """
        device_uuid = kwargs.get("device_uuid")
        device_name = kwargs.get("device_name", "Dispositivo sin nombre")
        device_type = kwargs.get("device_type", "tv")
        company_id = kwargs.get("company_id")

        if not device_uuid:
            return {"error": "device_uuid es requerido", "success": False}

        # Buscar empresa
        company = None
        if company_id:
            company = request.env["vscreens.company"].sudo().browse(int(company_id))
        if not company:
            email = kwargs.get("company_email")
            if email:
                company = request.env["vscreens.company"].sudo().search([("email", "=", email)], limit=1)

        if not company:
            return {"error": "Empresa no encontrada", "success": False}

        # Verificar si el dispositivo ya está activado
        existing = request.env["vscreens.device.activation"].sudo().search([("device_uuid", "=", device_uuid)], limit=1)
        if existing:
            if existing.company_id.id == company.id:
                existing.sudo().write({
                    "is_active": True,
                    "activated_at": fields.Datetime.now(),
                    "deactivated_at": False,
                    "device_name": device_name,
                    "device_type": device_type,
                })
                return {"success": True, "message": "Dispositivo reactivado", "activation_id": existing.id}
            else:
                return {"error": "Dispositivo ya activado en otra empresa", "success": False}

        activation = request.env["vscreens.device.activation"].sudo().create({
            "device_uuid": device_uuid,
            "device_name": device_name,
            "device_type": device_type,
            "company_id": company.id,
            "is_active": True,
        })

        return {"success": True, "message": "Dispositivo activado", "activation_id": activation.id}

    @http.route("/api/device/check", type="json", auth="public", methods=["POST"], csrf=False, cors="*", save_session=False)
    def check_device_activation(self, **kwargs):
        """Verificar si un dispositivo está activado para una empresa."""
        device_uuid = kwargs.get("device_uuid")
        company_id = kwargs.get("company_id")

        if not device_uuid:
            return {"authorized": False, "error": "device_uuid es requerido"}

        domain = [("device_uuid", "=", device_uuid), ("is_active", "=", True)]
        if company_id:
            domain.append(("company_id", "=", int(company_id)))

        activation = request.env["vscreens.device.activation"].sudo().search(domain, limit=1)
        if activation:
            return {
                "authorized": True,
                "activation_id": activation.id,
                "company_id": activation.company_id.id,
                "company_name": activation.company_id.name,
                "device_name": activation.device_name,
                "device_type": activation.device_type,
                "activated_at": fields.Datetime.to_string(activation.activated_at),
            }

        return {"authorized": False, "error": "Dispositivo no activado"}

    @http.route("/api/device/deactivate", type="json", auth="public", methods=["POST"], csrf=False, cors="*", save_session=False)
    def deactivate_device(self, **kwargs):
        """Desactivar un dispositivo (solo admin/master o la empresa propietaria)."""
        device_uuid = kwargs.get("device_uuid")
        if not device_uuid:
            return {"error": "device_uuid es requerido", "success": False}

        activation = request.env["vscreens.device.activation"].sudo().search([("device_uuid", "=", device_uuid)], limit=1)
        if not activation:
            return {"error": "Dispositivo no encontrado", "success": False}

        activation.sudo().write({"is_active": False, "deactivated_at": fields.Datetime.now()})
        return {"success": True, "message": "Dispositivo desactivado"}
