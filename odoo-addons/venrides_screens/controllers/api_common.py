import json
import hashlib

from odoo import fields, http
from odoo.http import request


CORS = "*"


def json_response(data, status=200):
    return request.make_json_response(data, status=status)


def error(status, detail):
    return json_response({"detail": detail}, status=status)


def payload():
    if request.httprequest.form:
        return {key: request.httprequest.form.get(key) for key in request.httprequest.form}
    raw = request.httprequest.get_data(as_text=True) or "{}"
    try:
        return json.loads(raw)
    except Exception:
        return {}


def client_ip():
    forwarded = request.httprequest.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.httprequest.remote_addr or "unknown"


def bearer_user():
    header = request.httprequest.headers.get("Authorization", "")
    if not header.lower().startswith("bearer "):
        return request.env["res.users"]
    token_value = header[7:].strip()
    token = request.env["venrides.api.token"].sudo().search(
        [("token", "=", token_value), ("active", "=", True)], limit=1
    )
    if not token or token.expires_at < fields.Datetime.now():
        return request.env["res.users"]
    token.sudo().write({"last_used_at": fields.Datetime.now()})
    return token.user_id.sudo()


def role_of(user):
    if not user:
        return None
    if user.has_group("venrides_screens.group_venrides_master"):
        return "admin_master"
    if user.has_group("venrides_screens.group_venrides_company_admin"):
        return "admin_empresa"
    if user.has_group("venrides_screens.group_venrides_basic"):
        return "user_basic"
    return "operador_empresa"


def is_master(user):
    return bool(user and user.has_group("venrides_screens.group_venrides_master"))


def company_of(user):
    return user.venrides_company_id if user else request.env["venrides.company"]


def company_or_404(company_id):
    company = request.env["venrides.company"].sudo().browse(int(company_id)).exists()
    return company


def device_or_404(uuid):
    return request.env["venrides.device"].sudo().search([("uuid", "=", uuid)], limit=1)


def can_access_company(user, company):
    if not user or not company:
        return False
    if is_master(user):
        return True
    return user.venrides_company_id.id == company.id


def public_url():
    return request.env["ir.config_parameter"].sudo().get_param(
        "venrides.api_public_url", "https://venrides-api.inverpave.com"
    )


def hash_ip(ip):
    return hashlib.sha256(f"venrides-{ip}".encode()).hexdigest()[:12]


def user_dict(user):
    return user.api_dict() if user else None
