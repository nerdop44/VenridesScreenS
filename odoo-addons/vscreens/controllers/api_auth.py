import secrets
import string
from datetime import timedelta

from odoo import fields, http
from odoo.http import request

from .api_common import (
    bearer_user,
    can_access_company,
    client_ip,
    company_of,
    error,
    is_master,
    json_response,
    payload,
    role_of,
    user_dict,
)


class VScreenSAuthController(http.Controller):

    def _login(self):
        data = payload()
        login = (data.get("username") or data.get("login") or "").strip()
        password = data.get("password") or ""
        if not login or not password:
            return error(400, "Usuario y contraseña son obligatorios")

        try:
            auth_info = request.env["res.users"].sudo().authenticate(
                {"type": "password", "login": login, "password": password},
                {"interactive": False, "REMOTE_ADDR": client_ip()},
            )
            uid = auth_info.get("uid")
        except Exception:
            return error(401, "Credenciales incorrectas")

        user = request.env["res.users"].sudo().browse(uid).exists()
        if not user or not user.active:
            return error(403, "Cuenta suspendida o inactiva")

        now = fields.Datetime.now()
        request.env["vscreens.api.token"].sudo().search([("expires_at", "<", now)]).unlink()
        token_value = secrets.token_urlsafe(48)
        request.env["vscreens.api.token"].sudo().create({
            "token": token_value,
            "user_id": user.id,
            "expires_at": now + timedelta(days=1),
        })

        return json_response({
            "access_token": token_value,
            "token_type": "bearer",
            "user": user_dict(user),
        })

    @http.route("/login/token", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def login_token(self, **kwargs):
        return self._login()

    @http.route("/auth/login", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def auth_login(self, **kwargs):
        return self._login()

    @http.route("/auth/forgot-password", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def forgot_password(self, **kwargs):
        data = payload()
        login = (data.get("username") or data.get("login") or "").strip()
        user = request.env["res.users"].sudo().search([("login", "=", login)], limit=1)
        if user:
            chars = string.ascii_letters + string.digits
            temp_password = "".join(secrets.choice(chars) for _ in range(12))
            user.sudo().write({
                "password": temp_password,
                "vscreens_must_change_password": True,
            })
            body = f"""
                <p>Hola,</p>
                <p>Has solicitado recuperar tu contraseña de VScreenS.</p>
                <p>Tu contraseña temporal es: <strong>{temp_password}</strong></p>
                <p>Por seguridad, deberás cambiarla al iniciar sesión.</p>
                <p>Si no solicitaste este cambio, ignora este correo.</p>
            """
            try:
                mail = request.env["mail.mail"].sudo().create({
                    "subject": "Recuperación de contraseña — VScreenS",
                    "body_html": body,
                    "email_to": user.login,
                    "email_from": request.env["ir.config_parameter"].sudo().get_str(
                        "vscreens.notification_email", "soporte@inverpave.com"
                    ),
                })
                mail.send()
            except Exception:
                pass
        return json_response({"message": "Si el correo existe, recibirá instrucciones."})

    @http.route("/auth/change-password", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def change_password(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        data = payload()
        old_password = data.get("old_password") or ""
        new_password = data.get("new_password") or ""
        if not old_password or not new_password:
            return error(400, "Contraseña actual y nueva son obligatorias")
        try:
            request.env["res.users"].sudo().authenticate(
                {"type": "password", "login": user.login, "password": old_password},
                {"interactive": False, "REMOTE_ADDR": client_ip()},
            )
        except Exception:
            return error(401, "La contraseña actual es incorrecta")
        user.sudo().write({
            "password": new_password,
            "vscreens_must_change_password": False,
        })
        return json_response({"message": "Contraseña actualizada correctamente"})

    @http.route("/admin/me", type="http", auth="public", methods=["PATCH", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def update_me(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        data = payload()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        if username and username != user.login:
            if not is_master(user):
                return error(403, "Solo el Administrador Maestro puede cambiar nombres de usuario")
            if request.env["res.users"].sudo().search_count([("login", "=", username), ("id", "!=", user.id)]):
                return error(400, "El nombre de usuario ya está en uso")
            user.sudo().write({"login": username})
        if password:
            user.sudo().write({"password": password, "vscreens_must_change_password": False})
        return json_response({"id": user.id, "username": user.login, "role": role_of(user)})

    @http.route("/admin/master-info", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def master_info(self, **kwargs):
        master = request.env["res.users"].sudo().search(
            [("group_ids", "in", request.env.ref("vscreens.group_vscreens_master").id)], limit=1
        )
        if not master:
            return error(404, "Administrador Maestro no encontrado")
        return json_response({"id": master.id, "username": master.login})

    @http.route("/admin/users/", type="http", auth="public", methods=["GET", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def users(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        if request.httprequest.method == "GET":
            domain = []
            if not is_master(user):
                if role_of(user) != "admin_empresa":
                    return error(403, "No tiene permiso")
                domain = [("vscreens_company_id", "=", company_of(user).id)]
            users = request.env["res.users"].sudo().search(domain)
            return json_response([u.api_dict() for u in users])

        data = payload()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        role = data.get("role") or "operador_empresa"
        company_id = data.get("company_id")
        if not username or not password:
            return error(400, "Username y password son obligatorios")
        if not is_master(user):
            if role_of(user) != "admin_empresa":
                return error(403, "No tiene permiso para crear usuarios")
            if role != "operador_empresa":
                return error(403, "Solo puede crear operadores")
            own_company = company_of(user)
            if company_id and int(company_id) != own_company.id:
                return error(403, "No puede crear usuarios en otra empresa")
            company_id = own_company.id
        if request.env["res.users"].sudo().search_count([("login", "=", username)]):
            return error(400, "El correo electrónico ya está registrado")
        company = request.env["vscreens.company"].sudo().browse(int(company_id)).exists() if company_id else False
        if company:
            if not company._plan_allows("allow_multi_user") and company.user_ids:
                return error(403, "Tu plan no permite múltiples usuarios")
            max_users = company.plan_id.max_users if company.plan_id else 1
            if max_users and len(company.user_ids) >= max_users:
                return error(400, f"Límite de usuarios alcanzado ({max_users})")
        new_user = request.env["res.users"].sudo().create({
            "login": username,
            "name": data.get("name") or username,
            "password": password,
            "vscreens_role": role,
            "vscreens_company_id": company.id if company else False,
            "vscreens_permissions": data.get("permissions") or {},
            "vscreens_must_change_password": bool(data.get("must_change_password")),
        })
        return json_response(new_user.api_dict(), status=201)

    @http.route("/admin/users/<int:user_id>", type="http", auth="public", methods=["PATCH", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def update_user(self, user_id, **kwargs):
        actor = bearer_user()
        target = request.env["res.users"].sudo().browse(user_id).exists()
        if not actor or not target:
            return error(404, "Usuario no encontrado")
        if not is_master(actor):
            if role_of(actor) != "admin_empresa" or target.vscreens_company_id.id != company_of(actor).id or target.vscreens_role != "operador_empresa":
                return error(403, "No autorizado")
        data = payload()
        vals = {}
        if is_master(actor):
            if data.get("role"):
                vals["vscreens_role"] = data["role"]
            if "company_id" in data:
                company = request.env["vscreens.company"].sudo().browse(int(data["company_id"])).exists() if data.get("company_id") else False
                vals["vscreens_company_id"] = company.id if company else False
            if "permissions" in data:
                vals["vscreens_permissions"] = data.get("permissions") or {}
        if data.get("password"):
            vals["password"] = data["password"]
        if vals:
            target.sudo().write(vals)
        return json_response({"id": target.id, "username": target.login, "role": target.vscreens_role})

    @http.route("/admin/users/<int:user_id>/password", type="http", auth="public", methods=["PATCH", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def update_user_password(self, user_id, **kwargs):
        actor = bearer_user()
        target = request.env["res.users"].sudo().browse(user_id).exists()
        if not actor or not target:
            return error(404, "Usuario no encontrado")
        allowed = is_master(actor) or actor.id == target.id
        if not allowed and role_of(actor) == "admin_empresa":
            allowed = target.vscreens_company_id.id == company_of(actor).id and target.vscreens_role == "operador_empresa"
        if not allowed:
            return error(403, "No tiene permiso para cambiar esta contraseña")
        data = payload()
        if not data.get("password"):
            return error(400, "Contraseña obligatoria")
        target.sudo().write({"password": data["password"], "vscreens_must_change_password": False})
        return json_response({"message": "Contraseña actualizada correctamente"})

    @http.route("/admin/users/<int:user_id>/status", type="http", auth="public", methods=["PATCH", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def toggle_user_status(self, user_id, **kwargs):
        actor = bearer_user()
        target = request.env["res.users"].sudo().browse(user_id).exists()
        if not actor or not target:
            return error(404, "Usuario no encontrado")
        if not is_master(actor):
            if role_of(actor) != "admin_empresa" or target.vscreens_company_id.id != company_of(actor).id:
                return error(403, "No autorizado")
        if target.id == actor.id:
            return error(400, "No puedes desactivar tu propia cuenta")
        raw = request.httprequest.args.get("is_active", "true").lower()
        is_active = raw in ("1", "true", "yes")
        target.sudo().write({"active": is_active})
        return json_response({"message": "Estado actualizado", "is_active": is_active})

    @http.route("/admin/users/<int:user_id>", type="http", auth="public", methods=["DELETE", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def delete_user(self, user_id, **kwargs):
        actor = bearer_user()
        target = request.env["res.users"].sudo().browse(user_id).exists()
        if not actor or not target:
            return error(404, "Usuario no encontrado")
        if target.has_group("vscreens.group_vscreens_master"):
            return error(403, "No se puede eliminar al Administrador Maestro")
        if not is_master(actor):
            if role_of(actor) != "admin_empresa" or target.vscreens_company_id.id != company_of(actor).id or target.vscreens_role != "operador_empresa":
                return error(403, "No autorizado")
        target.sudo().unlink()
        return json_response({"message": "Usuario eliminado correctamente"})

    @http.route("/admin/all-users", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def all_users(self, **kwargs):
        user = bearer_user()
        if not user or not is_master(user):
            return error(403, "Acceso solo para nivel Maestro")
        users = request.env["res.users"].sudo().search([])
        return json_response([u.api_dict() for u in users])
