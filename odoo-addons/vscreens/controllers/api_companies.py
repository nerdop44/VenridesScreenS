import re
from io import BytesIO

from odoo import fields, http
from odoo.http import request

from .api_common import (
    bearer_user,
    can_access_company,
    company_or_404,
    error,
    is_master,
    json_response,
    payload,
    role_of,
    company_of,
)


def _to_datetime(value):
    if not value:
        return False
    if isinstance(value, str):
        try:
            return fields.Datetime.to_datetime(value)
        except Exception:
            try:
                return fields.Datetime.to_datetime(value.replace("Z", ""))
            except Exception:
                return False
    return value


def _to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _extract_colors(binary):
    try:
        from PIL import Image

        image = Image.open(BytesIO(binary)).convert("RGB")
        image.thumbnail((96, 96))
        colors = image.getcolors(maxcolors=96 * 96) or []
        colors.sort(key=lambda item: item[0], reverse=True)
        picked = []
        for _, rgb in colors:
            hex_color = "#{:02x}{:02x}{:02x}".format(*rgb)
            if hex_color not in picked:
                picked.append(hex_color)
            if len(picked) == 3:
                break
        while len(picked) < 3:
            picked.append(picked[-1] if picked else "#000000")
        return {"primary": picked[0], "secondary": picked[1], "accent": picked[2]}
    except Exception:
        return {"primary": "#1a202c", "secondary": "#2d3748", "accent": "#4a5568"}


class VScreenSCompanyController(http.Controller):

    @http.route("/companies/", type="http", auth="public", methods=["GET", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def companies(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        if request.httprequest.method == "GET":
            if not is_master(user):
                return error(403, "No tiene permiso para ver empresas")
            companies = request.env["vscreens.company"].sudo().search([])
            return json_response([
                {
                    "id": c.id,
                    "name": c.name,
                    "plan": c.plan_code or "free",
                    "is_active": c.is_active,
                    "max_screens": c.max_screens_effective,
                    "active_screens": c.active_screens,
                    "total_screens": c.total_screens,
                }
                for c in companies
            ])

        if not is_master(user):
            return error(403, "Solo el Administrador Maestro puede crear empresas")
        data = payload()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        name = (data.get("name") or "").strip()
        if not name or not username or not password:
            return error(400, "Nombre, usuario y contraseña son obligatorios")
        if request.env["res.users"].sudo().search_count([("login", "=", username)]):
            return error(400, "El correo del administrador ya está registrado")

        plan = request.env["vscreens.plan"].sudo().search([("code", "=", data.get("plan") or "free")], limit=1)
        if not plan:
            plan = request.env["vscreens.plan"].sudo().search([("code", "=", "free")], limit=1)
        company = request.env["vscreens.company"].sudo().create({
            "name": name,
            "plan_id": plan.id if plan else False,
            "max_screens": _to_int(data.get("max_screens"), plan.max_screens if plan else 2),
            "valid_until": _to_datetime(data.get("valid_until")),
            "rif": data.get("rif"),
            "address": data.get("address"),
            "phone": data.get("phone"),
            "whatsapp": data.get("whatsapp"),
            "instagram": data.get("instagram"),
            "facebook": data.get("facebook"),
            "tiktok": data.get("tiktok"),
            "contact_person": data.get("contact_person"),
            "email": data.get("email"),
            "client_editable_fields": data.get("client_editable_fields") or "",
            "layout_type": data.get("layout_type") or "layout-a",
            "filler_keywords": data.get("filler_keywords") or "nature, food",
            "google_drive_link": data.get("google_drive_link"),
            "video_source": data.get("video_source") or "youtube",
            "priority_content_url": data.get("priority_content_url"),
            "video_playlist": data.get("video_playlist") or [],
            "sidebar_content": data.get("sidebar_content") or [],
            "bottom_bar_content": data.get("bottom_bar_content") or {},
            "design_settings": data.get("design_settings") or {},
            "pause_duration": _to_int(data.get("pause_duration"), 10),
        })

        role = "user_basic" if (plan and plan.code == "free") else "admin_empresa"
        request.env["res.users"].sudo().create({
            "login": username,
            "name": data.get("contact_person") or name,
            "password": password,
            "vscreens_role": role,
            "vscreens_company_id": company.id,
        })
        if role != "user_basic":
            request.env["res.users"].sudo().create({
                "login": f"op.{username}",
                "name": f"Operador {name}",
                "password": password,
                "vscreens_role": "operador_empresa",
                "vscreens_company_id": company.id,
            })
        return json_response(company.api_dict(), status=201)

    @http.route("/companies/<int:company_id>", type="http", auth="public", methods=["GET", "PATCH", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def company_detail(self, company_id, **kwargs):
        user = bearer_user()
        company = company_or_404(company_id)
        if not user or not company:
            return error(404, "Empresa no encontrada")
        if not can_access_company(user, company):
            return error(403, "No tiene acceso a los datos de esta empresa")

        if request.httprequest.method == "GET":
            return json_response(company.api_dict())

        data = payload()
        if not is_master(user) and any(field in data for field in ("plan", "max_screens", "valid_until", "is_active")):
            return error(403, "Solo el Administrador Maestro puede cambiar el plan, límites o vigencia")
        if not is_master(user):
            if "sidebar_content" in data and not company._plan_allows("allow_sidebar"):
                return error(403, "Tu plan no incluye editor de barra lateral")
            if "bottom_bar_content" in data and not company._plan_allows("allow_bottom_bar"):
                return error(403, "Tu plan no incluye barra inferior")
            if "video_playlist" in data and not company._plan_allows("allow_video_playlist"):
                return error(403, "Tu plan no incluye playlist de videos")
            if "priority_content_url" in data and not company._plan_allows("allow_priority_content"):
                return error(403, "Tu plan no incluye contenido prioritario")
            if "design_settings" in data and not company._plan_allows("allow_custom_branding"):
                return error(403, "Tu plan no incluye branding personalizado")
        profile_fields = {"name", "rif", "address", "phone", "contact_person", "email"}
        if not is_master(user):
            if not company.can_edit_profile and any(field in data for field in profile_fields):
                return error(403, "Edición de perfil (Datos de Empresa) deshabilitada. Contacte al administrador.")
            if any(field in data for field in profile_fields):
                data["can_edit_profile"] = False
                data["has_edited_profile"] = True
            if role_of(user) == "operador_empresa":
                allowed = {"video_playlist", "priority_content_url", "video_source"}
                data = {key: value for key, value in data.items() if key in allowed}

        allowed_fields = {
            "name", "layout_type", "primary_color", "secondary_color", "accent_color",
            "max_screens", "valid_until", "filler_keywords", "google_drive_link",
            "video_source", "video_playlist", "can_edit_profile", "has_edited_profile",
            "rif", "address", "phone", "whatsapp", "instagram", "facebook", "tiktok",
            "contact_person", "email", "client_editable_fields", "sidebar_header_type",
            "sidebar_header_value", "priority_content_url", "ad_frequency",
            "sidebar_content", "bottom_bar_content", "design_settings", "pause_duration",
            "logo_url",
        }
        vals = {}
        for key, value in data.items():
            if key == "plan":
                plan = request.env["vscreens.plan"].sudo().search([("code", "=", value)], limit=1)
                if plan:
                    vals["plan_id"] = plan.id
            elif key == "valid_until":
                vals[key] = _to_datetime(value)
            elif key == "max_screens":
                vals[key] = _to_int(value, company.max_screens)
            elif key == "design_settings":
                current = company.design_settings if isinstance(company.design_settings, dict) else {}
                merged = dict(current)
                if isinstance(value, dict):
                    merged.update(value)
                vals[key] = merged
            elif key in allowed_fields:
                vals[key] = value
        if vals:
            company.sudo().write(vals)
        return json_response(company.api_dict())

    @http.route("/companies/<int:company_id>/preview-config", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def preview_config(self, company_id, **kwargs):
        company = company_or_404(company_id)
        if not company:
            return error(404, "Empresa no encontrada")
        return json_response(company.preview_config())

    @http.route("/companies/<int:company_id>/toggle", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def toggle_company(self, company_id, **kwargs):
        user = bearer_user()
        company = company_or_404(company_id)
        if not user or not company:
            return error(404, "Empresa no encontrada")
        if not is_master(user):
            return error(403, "Solo el Administrador Maestro puede suspender empresas")
        company.sudo().write({"is_active": not company.is_active})
        return json_response({"is_active": company.is_active})

    @http.route("/companies/<int:company_id>/credentials", type="http", auth="public", methods=["PATCH", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def update_credentials(self, company_id, **kwargs):
        user = bearer_user()
        company = company_or_404(company_id)
        if not user or not company:
            return error(404, "Empresa no encontrada")
        if not can_access_company(user, company) or not (is_master(user) or role_of(user) == "admin_empresa"):
            return error(403, "No autorizado")
        data = payload()
        target = company.user_ids.filtered(lambda u: u.vscreens_role == "admin_empresa")[:1] or company.user_ids[:1]
        if not target:
            return error(404, "Usuario no encontrado")
        vals = {}
        if data.get("username"):
            vals["login"] = data["username"]
        if data.get("password"):
            vals["password"] = data["password"]
        if vals:
            target.sudo().write(vals)
        return json_response({"message": "Credenciales actualizadas correctamente"})

    @http.route("/companies/<int:company_id>/logo", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def upload_logo(self, company_id, **kwargs):
        user = bearer_user()
        company = company_or_404(company_id)
        if not user or not company:
            return error(404, "Empresa no encontrada")
        if not can_access_company(user, company):
            return error(403, "No autorizado")
        if not company._plan_allows("allow_custom_branding"):
            return error(403, "Tu plan no incluye branding personalizado")
        upload = request.httprequest.files.get("file")
        if not upload:
            return error(400, "Archivo requerido")
        binary = upload.read()
        ext = (upload.filename.rsplit(".", 1)[-1] if "." in upload.filename else "png").lower()
        filename = f"{company.id}_logo.{ext}"
        colors = _extract_colors(binary)
        company.sudo().write({
            "logo": binary,
            "logo_filename": upload.filename,
            "logo_url": f"/api/logos/{filename}",
            "primary_color": colors["primary"],
            "secondary_color": colors["secondary"],
            "accent_color": colors["accent"],
        })
        return json_response({"logo_url": company.logo_url, "colors": colors})

    @http.route("/companies/<int:company_id>/sidebar-bg", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def upload_sidebar_bg(self, company_id, **kwargs):
        user = bearer_user()
        company = company_or_404(company_id)
        if not user or not company:
            return error(404, "Empresa no encontrada")
        if not can_access_company(user, company):
            return error(403, "No autorizado")
        if not company._plan_allows("allow_custom_branding"):
            return error(403, "Tu plan no incluye branding personalizado")
        upload = request.httprequest.files.get("file")
        if not upload:
            return error(400, "Archivo requerido")
        binary = upload.read()
        ext = (upload.filename.rsplit(".", 1)[-1] if "." in upload.filename else "png").lower()
        filename = f"{company.id}_sidebar.{ext}"
        settings = dict(company.design_settings or {})
        settings["sidebar_bg_image"] = f"/api/logos/{filename}"
        company.sudo().write({
            "sidebar_bg": binary,
            "sidebar_bg_filename": upload.filename,
            "design_settings": settings,
        })
        return json_response(company.api_dict())

    @http.route("/admin/companies/<int:company_id>/devices", type="http", auth="public", methods=["GET", "DELETE", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def company_devices(self, company_id, **kwargs):
        user = bearer_user()
        company = company_or_404(company_id)
        if not user or not company:
            return error(404, "Empresa no encontrada")
        if not can_access_company(user, company):
            return error(403, "No autorizado")
        if request.httprequest.method == "DELETE":
            if not (is_master(user) or role_of(user) in ("admin_empresa", "operador_empresa")):
                return error(403, "No autorizado")
            company.device_ids.sudo().unlink()
            return json_response({"message": "Todos los dispositivos han sido desvinculados correctamente"})
        return json_response([device.api_dict() for device in company.device_ids])

    @http.route("/admin/companies/<int:company_id>/menus", type="http", auth="public", methods=["GET", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def company_menus(self, company_id, **kwargs):
        user = bearer_user()
        company = company_or_404(company_id)
        if not user or not company or not can_access_company(user, company):
            return error(404, "Empresa no encontrada")
        if request.httprequest.method == "GET":
            return json_response([item.api_dict() for item in company.menu_item_ids])
        data = payload()
        item = request.env["vscreens.menu.item"].sudo().create({
            "company_id": company.id,
            "name": data.get("name") or "Nuevo ítem",
            "price": data.get("price") or 0.0,
            "category": data.get("category") or "",
            "is_available": data.get("is_available", True),
        })
        return json_response(item.api_dict(), status=201)

    @http.route("/admin/menus/<int:menu_id>", type="http", auth="public", methods=["DELETE", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def delete_menu(self, menu_id, **kwargs):
        user = bearer_user()
        item = request.env["vscreens.menu.item"].sudo().browse(menu_id).exists()
        if not user or not item:
            return error(404, "Ítem no encontrado")
        if not can_access_company(user, item.company_id):
            return error(403, "No autorizado")
        item.sudo().unlink()
        return json_response({"status": "ok"})

    @http.route("/companies/<int:company_id>/message", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def send_alert(self, company_id, **kwargs):
        user = bearer_user()
        company = company_or_404(company_id)
        if not user or not company:
            return error(404, "Empresa no encontrada")
        if not can_access_company(user, company):
            return error(403, "No tiene permiso para enviar mensajes a esta empresa")
        if role_of(user) == "operador_empresa":
            return error(403, "No tiene permisos suficientes")
        data = payload()
        body = (data.get("text") or data.get("body") or "").strip()
        if not body:
            return error(400, "Mensaje requerido")
        request.env["vscreens.message"].sudo().create({
            "company_id": company.id,
            "sender_id": user.id,
            "subject": "¡AVISO IMPORTANTE!",
            "body": body,
            "is_alert": True,
            "alert_duration": _to_int(data.get("duration"), 15),
            "is_read": False,
        })
        return json_response({"message": "Alerta enviada a pantallas", "duration": _to_int(data.get("duration"), 15)})

    @http.route("/admin/companies/<int:company_id>", type="http", auth="public", methods=["DELETE", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def delete_company(self, company_id, **kwargs):
        user = bearer_user()
        company = company_or_404(company_id)
        if not user or not company:
            return error(404, "Empresa no encontrada")
        if not is_master(user):
            return error(403, "Solo el Administrador Maestro puede eliminar empresas")
        company.sudo().unlink()
        return json_response({"message": "Empresa eliminada correctamente"})
