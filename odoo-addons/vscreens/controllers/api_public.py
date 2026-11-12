import mimetypes
import os
from datetime import datetime, timedelta
from collections import defaultdict

from odoo import fields, http
from odoo.http import request

from .api_common import (
    bearer_user,
    client_ip,
    error,
    hash_ip,
    is_master,
    json_response,
    payload,
    public_url,
)


def _send_notification(subject, body, email_to):
    try:
        request.env["mail.mail"].sudo().create({
            "subject": subject,
            "body_html": body,
            "email_to": email_to,
            "email_from": request.env["ir.config_parameter"].sudo().get_str(
                "vscreens.notification_email", "info.vscreens@inverpave.com"
            ),
        }).send()
    except Exception:
        pass


class VScreenSPublicController(http.Controller):

    @http.route("/api/plans", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def plans(self, **kwargs):
        return json_response(request.env["vscreens.plan"].sudo().api_list())

    @http.route("/finance/bcv", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def bcv(self, **kwargs):
        from ..models.vscreens_currency import get_bcv_rate

        rate = get_bcv_rate(request.env)
        updated = request.env["ir.config_parameter"].sudo().get_str("vscreens.bcv_rate_updated", "")
        return json_response({"usd_to_ves": rate, "last_updated": updated or None})

    @http.route("/api/logos/<string:filename>", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def logo(self, filename, **kwargs):
        parts = filename.split("_", 1)
        if len(parts) != 2 or not parts[0].isdigit():
            return error(404, "Archivo no encontrado")
        company = request.env["vscreens.company"].sudo().browse(int(parts[0])).exists()
        if not company:
            return error(404, "Archivo no encontrado")
        lower = filename.lower()
        if "_sidebar." in lower:
            binary = company.sidebar_bg
        elif "_logo." in lower:
            binary = company.logo
        else:
            return error(404, "Archivo no encontrado")
        if not binary:
            return error(404, "Archivo no encontrado")
        import base64

        content = base64.b64decode(binary)
        mimetype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        return request.make_response(content, headers=[("Content-Type", mimetype), ("Cache-Control", "public, max-age=300")])

    @http.route("/api/forms/contact", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def contact(self, **kwargs):
        data = payload()
        if data.get("website") or data.get("hp_field") or data.get("url"):
            return json_response({"message": "Gracias por tu mensaje.", "status": "success"})
        name = (data.get("nombre") or "").strip()
        email = (data.get("email") or "").strip()
        if not name or not email:
            return error(400, "Nombre y email son obligatorios")
        notes = f"{data.get('asunto') or ''}: {data.get('mensaje') or ''}".strip()
        request.env["crm.lead"].sudo().create({
            "name": f"Contacto web — {name}",
            "contact_name": name,
            "email_from": email,
            "phone": data.get("telefono") or "",
            "description": notes,
            "type": "lead",
            "vscreens_contact_name": name,
            "vscreens_source_detail": "contact_form",
        })
        _send_notification(
            f"Nuevo contacto: {name}",
            f"<p><strong>Nombre:</strong> {name}</p><p><strong>Email:</strong> {email}</p><p><strong>Teléfono:</strong> {data.get('telefono','')}</p><p><strong>Mensaje:</strong> {data.get('mensaje','')}</p>",
            request.env["ir.config_parameter"].sudo().get_str("vscreens.notification_email", "info.vscreens@inverpave.com"),
        )
        return json_response({"message": "¡Gracias! Tu mensaje ha sido recibido. Te contactaremos pronto.", "status": "success"})

    @http.route("/api/forms/signup/plan", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def signup_plan(self, **kwargs):
        data = payload()
        if data.get("website") or data.get("hp_field") or data.get("url"):
            return json_response({"message": "Registro recibido.", "status": "success"})
        name = (data.get("nombre") or "").strip()
        email = (data.get("email") or "").strip()
        if not name or not email:
            return error(400, "Nombre y email son obligatorios")
        plan = data.get("plan") or ""
        request.env["crm.lead"].sudo().create({
            "name": f"Solicitud de plan {plan} — {name}",
            "contact_name": name,
            "email_from": email,
            "phone": data.get("telefono") or "",
            "partner_name": data.get("empresa") or "",
            "description": data.get("mensaje") or "",
            "type": "lead",
            "vscreens_plan_interest": plan,
            "vscreens_source_detail": "plan_signup",
            "vscreens_contact_name": name,
        })
        _send_notification(
            f"Nueva solicitud de plan {plan} — {name}",
            f"<p><strong>Plan:</strong> {plan}</p><p><strong>Nombre:</strong> {name}</p><p><strong>Email:</strong> {email}</p><p><strong>Empresa:</strong> {data.get('empresa','')}</p><p><strong>Teléfono:</strong> {data.get('telefono','')}</p>",
            request.env["ir.config_parameter"].sudo().get_str("vscreens.notification_email", "info.vscreens@inverpave.com"),
        )
        return json_response({"message": "¡Gracias! Hemos recibido tu solicitud. Te contactaremos pronto.", "status": "success"})

    @http.route("/api/analytics/track", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def analytics_track(self, **kwargs):
        data = payload()
        user_agent = request.httprequest.headers.get("user-agent", "")
        device = "desktop"
        lowered = user_agent.lower()
        if any(token in lowered for token in ("mobile", "android", "iphone")):
            device = "mobile"
        elif any(token in lowered for token in ("ipad", "tablet")):
            device = "tablet"
        elif any(token in lowered for token in ("bot", "crawl", "spider")):
            device = "bot"
        if device != "bot":
            request.env["vscreens.analytics.visit"].sudo().create({
                "page": data.get("page") or "/",
                "referrer": data.get("referrer") or request.httprequest.headers.get("referer", ""),
                "device": device,
                "ip_hash": hash_ip(client_ip()),
                "user_agent": user_agent,
            })
        return json_response({"status": "ok"})

    @http.route("/admin/analytics/dashboard", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def analytics_dashboard(self, **kwargs):
        user = bearer_user()
        if not user or not is_master(user):
            return error(401, "No autorizado")
        visits = request.env["vscreens.analytics.visit"].sudo().search([])
        now = datetime.now()
        today = now.date()
        yesterday = today - timedelta(days=1)
        trend = defaultdict(int)
        pages = defaultdict(int)
        referrers = defaultdict(int)
        devices = defaultdict(int)
        unique_today = set()
        for visit in visits:
            date = visit.visit_date.date()
            if date >= today - timedelta(days=29):
                trend[date.isoformat()] += 1
            pages[visit.page] += 1
            referrers[visit.referrer or "directo"] += 1
            devices[visit.device or "desktop"] += 1
            if date == today:
                unique_today.add(visit.ip_hash)
        return json_response({
            "total_visits": len(visits),
            "visits_today": trend.get(today.isoformat(), 0),
            "visits_yesterday": trend.get(yesterday.isoformat(), 0),
            "unique_today": len(unique_today),
            "trend_30d": dict(sorted(trend.items())),
            "top_pages": dict(sorted(pages.items(), key=lambda item: item[1], reverse=True)[:10]),
            "referrers": dict(sorted(referrers.items(), key=lambda item: item[1], reverse=True)[:10]),
            "devices": dict(devices),
            "recent_visits": [visit.api_dict() for visit in visits[:30]],
        })

    @http.route("/api/benry/chat", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def benry_chat(self, **kwargs):
        data = payload()
        session_id = data.get("session_id") or "guest"
        message = (data.get("message") or "").strip()
        if not message:
            return error(400, "Mensaje requerido")
        result = request.env["vscreens.benry"].sudo().chat(session_id, message)
        return json_response(result)

    @http.route("/api/benry/lead", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def benry_lead(self, **kwargs):
        data = payload()
        if data.get("email"):
            request.env["crm.lead"].sudo().create({
                "name": f"Lead Benry — {data.get('nombre') or data['email']}",
                "contact_name": data.get("nombre") or "",
                "email_from": data.get("email"),
                "phone": data.get("telefono") or "",
                "description": f"Sesión: {data.get('session_id','')}",
                "type": "lead",
                "vscreens_plan_interest": data.get("plan_interes") or "",
                "vscreens_source_detail": "benry",
            })
        return json_response({"message": "Lead registrado exitosamente", "status": "success"})

    @http.route("/api/benry/session/<string:session_id>", type="http", auth="public", methods=["DELETE", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def benry_clear(self, session_id, **kwargs):
        request.env["vscreens.benry"].sudo().clear_session(session_id)
        return json_response({"status": "ok"})

    @http.route("/downloads/tv", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def download_tv(self, **kwargs):
        path = request.env["ir.config_parameter"].sudo().get_str(
            "vscreens.apk_path", "/opt/vscreens/releases/VScreenS_TV.apk"
        )
        if not path or not os.path.exists(path):
            return error(404, "APK no disponible")
        with open(path, "rb") as handle:
            content = handle.read()
        return request.make_response(content, headers=[
            ("Content-Type", "application/vnd.android.package-archive"),
            ("Content-Disposition", 'attachment; filename="VScreenS_TV.apk"'),
        ])

    @http.route("/api/downloads/tv/short-url", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def short_url(self, **kwargs):
        return json_response({"url": f"{public_url()}/downloads/tv"})
