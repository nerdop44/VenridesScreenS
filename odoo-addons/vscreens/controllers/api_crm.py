from datetime import datetime, timedelta

from odoo import fields, http
from odoo.http import request

from .api_common import bearer_user, error, is_master, json_response, payload


DEFAULT_TEMPLATES = {
    "welcome": {
        "subject": "¡Bienvenido a VScreenS! 📺",
        "body": "<p>Hola {{contacto}} de {{nombre_empresa}},</p><p>Bienvenido a VScreenS. Ya puedes gestionar tus pantallas desde el panel.</p>",
        "category": "bienvenida",
    },
    "expiry_reminder": {
        "subject": "⚠️ Tu plan VScreenS vence pronto",
        "body": "<p>Hola {{contacto}}, tu plan {{plan}} vence el {{fecha_vencimiento}}.</p><p>Renueva para evitar interrupciones.</p>",
        "category": "cobranza",
    },
    "payment_confirmation": {
        "subject": "Confirmación de pago — VScreenS ✅",
        "body": "<p>Hemos recibido tu pago, {{contacto}}.</p><p>Empresa: {{nombre_empresa}}</p><p>Monto: {{monto_pago}}</p>",
        "category": "cobranza",
    },
    "birthday_greeting": {
        "subject": "¡Feliz cumpleaños de parte de VScreenS! 🎂",
        "body": "<p>¡Felicidades, {{contacto}}!</p><p>Disfruta tu día.</p>",
        "category": "marketing",
    },
    "holiday_greeting": {
        "subject": "¡Felices fiestas de parte de VScreenS! 🎄",
        "body": "<p>Hola {{contacto}}, te deseamos lo mejor en estas fiestas.</p>",
        "category": "marketing",
    },
    "apk_download": {
        "subject": "Tu app VScreenS para Smart TV 📺",
        "body": "<p>Hola {{contacto}}, ya puedes instalar VScreenS en tu Smart TV.</p><p>Descarga: {{short_url}}</p>",
        "category": "bienvenida",
    },
}

VARIABLES = [
    {"var": "{{nombre_empresa}}", "desc": "Nombre de la empresa", "example": "Café El Venezolano"},
    {"var": "{{contacto}}", "desc": "Persona de contacto", "example": "Juan Pérez"},
    {"var": "{{email}}", "desc": "Email de la empresa", "example": "info@empresa.com"},
    {"var": "{{telefono}}", "desc": "Teléfono de la empresa", "example": "+58 412 1234567"},
    {"var": "{{plan}}", "desc": "Plan actual", "example": "Plus"},
    {"var": "{{fecha_vencimiento}}", "desc": "Fecha de vencimiento", "example": "15/03/2026"},
    {"var": "{{pantallas_activas}}", "desc": "Pantallas activas", "example": "3"},
    {"var": "{{max_pantallas}}", "desc": "Máximo de pantallas", "example": "10"},
    {"var": "{{monto_pago}}", "desc": "Monto del pago", "example": "$50.00"},
    {"var": "{{fecha_hoy}}", "desc": "Fecha actual", "example": "15/02/2026"},
    {"var": "{{nombre_promo}}", "desc": "Nombre de la promoción", "example": "Black Friday"},
    {"var": "{{codigo_promo}}", "desc": "Código de descuento", "example": "BF2026"},
    {"var": "{{descuento}}", "desc": "Porcentaje de descuento", "example": "25%"},
    {"var": "{{whatsapp}}", "desc": "WhatsApp de la empresa", "example": "+58 412 1234567"},
    {"var": "{{short_url}}", "desc": "URL corta de descarga", "example": "https://vscreens-api.inverpave.com/downloads/tv"},
]


class VscreensCrmController(http.Controller):

    def _master(self):
        user = bearer_user()
        if not user:
            return None, error(401, "No autenticado")
        if not is_master(user):
            return None, error(403, "Solo el Administrador Maestro puede acceder al CRM")
        return user, None

    # ------------------------------------------------------------------
    # Plantillas
    # ------------------------------------------------------------------
    @http.route("/admin/crm/templates", type="http", auth="public", methods=["GET", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def templates(self, **kwargs):
        user, failure = self._master()
        if failure:
            return failure
        if request.httprequest.method == "GET":
            templates = request.env["vscreens.email.template"].sudo().search([], order="category, name")
            return json_response([
                {
                    "id": t.id, "name": t.name, "subject": t.subject, "body": t.body,
                    "default_subject": t.default_subject, "default_body": t.default_body,
                    "is_system": t.is_system, "category": t.category, "is_active": t.active,
                }
                for t in templates
            ])
        data = payload()
        name = (data.get("name") or "").strip()
        if not name:
            return error(400, "Nombre de plantilla requerido")
        template = request.env["vscreens.email.template"].sudo().search([("name", "=", name)], limit=1)
        vals = {
            "name": name,
            "subject": data.get("subject") or "",
            "body": data.get("body") or "",
            "category": data.get("category") or "general",
            "active": data.get("is_active", True),
        }
        if template:
            template.sudo().write(vals)
        else:
            template = request.env["vscreens.email.template"].sudo().create(vals)
        return json_response({"status": "success", "id": template.id})

    @http.route("/admin/crm/templates/<int:template_id>", type="http", auth="public", methods=["DELETE", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def delete_template(self, template_id, **kwargs):
        user, failure = self._master()
        if failure:
            return failure
        template = request.env["vscreens.email.template"].sudo().browse(template_id).exists()
        if not template:
            return error(404, "Plantilla no encontrada")
        if template.is_system:
            return error(403, "No se puede eliminar una plantilla del sistema. Use restaurar.")
        template.sudo().unlink()
        return json_response({"status": "deleted"})

    @http.route("/admin/crm/templates/<int:template_id>/revert", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def revert_template(self, template_id, **kwargs):
        user, failure = self._master()
        if failure:
            return failure
        template = request.env["vscreens.email.template"].sudo().browse(template_id).exists()
        if not template:
            return error(404, "Plantilla no encontrada")
        if not template.default_body:
            return error(400, "Esta plantilla no tiene versión original")
        template.sudo().write({
            "subject": template.default_subject or template.subject,
            "body": template.default_body,
        })
        return json_response({"status": "reverted"})

    @http.route("/admin/crm/templates/variables", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def template_variables(self, **kwargs):
        user, failure = self._master()
        if failure:
            return failure
        return json_response(VARIABLES)

    @http.route("/admin/crm/templates/seed", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def seed_templates(self, **kwargs):
        user, failure = self._master()
        if failure:
            return failure
        created = 0
        for name, data in DEFAULT_TEMPLATES.items():
            existing = request.env["vscreens.email.template"].sudo().search(
                [("name", "=", name), ("is_system", "=", True)], limit=1
            )
            if not existing:
                request.env["vscreens.email.template"].sudo().create({
                    "name": name,
                    "subject": data["subject"],
                    "body": data["body"],
                    "default_subject": data["subject"],
                    "default_body": data["body"],
                    "is_system": True,
                    "category": data["category"],
                })
                created += 1
        return json_response({"status": "success", "created": created})

    # ------------------------------------------------------------------
    # Calendario / feriados
    # ------------------------------------------------------------------
    @http.route("/admin/crm/calendar", type="http", auth="public", methods=["GET", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def calendar(self, **kwargs):
        user, failure = self._master()
        if failure:
            return failure
        if request.httprequest.method == "GET":
            activities = request.env["vscreens.calendar.activity"].sudo().search([], order="activity_date")
            return json_response([a.api_dict() for a in activities])
        data = payload()
        activity = request.env["vscreens.calendar.activity"].sudo().create({
            "title": data.get("title") or "Actividad",
            "description": data.get("description") or "",
            "activity_date": fields.Date.to_date(data.get("activity_date")) if data.get("activity_date") else fields.Date.today(),
            "is_holiday": data.get("is_holiday", False),
            "send_auto_greeting": data.get("send_auto_greeting", False),
        })
        return json_response({"status": "success", "id": activity.id}, status=201)

    @http.route("/admin/crm/calendar/<int:activity_id>", type="http", auth="public", methods=["DELETE", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def delete_calendar(self, activity_id, **kwargs):
        user, failure = self._master()
        if failure:
            return failure
        activity = request.env["vscreens.calendar.activity"].sudo().browse(activity_id).exists()
        if not activity:
            return error(404, "Actividad no encontrada")
        activity.sudo().unlink()
        return json_response({"status": "deleted"})

    @http.route("/admin/crm/calendar/holidays", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def seed_holidays(self, **kwargs):
        user, failure = self._master()
        if failure:
            return failure
        year = datetime.utcnow().year
        holidays = [
            ("Año Nuevo", 1, 1), ("Carnaval (Lunes)", 2, 16), ("Carnaval (Martes)", 2, 17),
            ("Jueves Santo", 4, 2), ("Viernes Santo", 4, 3), ("Declaración de Independencia", 4, 19),
            ("Día del Trabajador", 5, 1), ("Batalla de Carabobo", 6, 24), ("Día de la Independencia", 7, 5),
            ("Natalicio del Libertador", 7, 24), ("Día de la Resistencia Indígena", 10, 12),
            ("Navidad", 12, 25), ("Fin de Año", 12, 31),
        ]
        created = 0
        for title, month, day in holidays:
            existing = request.env["vscreens.calendar.activity"].sudo().search([
                ("title", "=", title), ("is_holiday", "=", True),
                ("activity_date", "=", datetime(year, month, day).date()),
            ], limit=1)
            if not existing:
                request.env["vscreens.calendar.activity"].sudo().create({
                    "title": title,
                    "description": f"Feriado Nacional: {title}",
                    "activity_date": datetime(year, month, day).date(),
                    "is_holiday": True,
                    "send_auto_greeting": True,
                })
                created += 1
        return json_response({"status": "success", "created": created})

    # ------------------------------------------------------------------
    # Leads / promociones / afiliados
    # ------------------------------------------------------------------
    @http.route("/admin/crm/leads", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def leads(self, **kwargs):
        user, failure = self._master()
        if failure:
            return failure
        leads = request.env["crm.lead"].sudo().search([("vscreens_source_detail", "!=", False)], order="create_date desc")
        return json_response([
            {
                "id": l.id, "name": l.contact_name or l.name, "email": l.email_from,
                "phone": l.phone, "source": l.vscreens_source_detail,
                "plan_interest": l.vscreens_plan_interest, "notes": l.description,
                "created_at": fields.Datetime.to_string(l.create_date) if l.create_date else None,
            }
            for l in leads
        ])

    @http.route("/admin/crm/promotions", type="http", auth="public", methods=["GET", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def promotions(self, **kwargs):
        user, failure = self._master()
        if failure:
            return failure
        if request.httprequest.method == "GET":
            return json_response([p.api_dict() for p in request.env["vscreens.promotion"].sudo().search([])])
        data = payload()
        promo = request.env["vscreens.promotion"].sudo().create({
            "name": data.get("name") or "Promoción",
            "code": data.get("code") or "",
            "discount_pct": data.get("discount_pct") or 0.0,
            "valid_from": fields.Datetime.to_datetime(data.get("valid_from")) if data.get("valid_from") else False,
            "valid_to": fields.Datetime.to_datetime(data.get("valid_to")) if data.get("valid_to") else False,
            "is_active": data.get("is_active", True),
        })
        return json_response({"status": "success", "id": promo.id}, status=201)

    @http.route("/admin/crm/affiliates", type="http", auth="public", methods=["GET", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def affiliates(self, **kwargs):
        user, failure = self._master()
        if failure:
            return failure
        if request.httprequest.method == "GET":
            return json_response([a.api_dict() for a in request.env["vscreens.affiliate"].sudo().search([])])
        data = payload()
        affiliate = request.env["vscreens.affiliate"].sudo().create({
            "name": data.get("name") or "Afiliado",
            "email": data.get("email") or "",
            "code": data.get("code") or "",
            "commission_pct": data.get("commission_pct") or 10.0,
        })
        return json_response({"status": "success", "id": affiliate.id}, status=201)

    @http.route("/admin/crm/ecosystem-status", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def ecosystem(self, **kwargs):
        user, failure = self._master()
        if failure:
            return failure
        companies = request.env["vscreens.company"].sudo().search([])
        devices = request.env["vscreens.device"].sudo().search([])
        thirty = datetime.utcnow() - timedelta(days=30)
        payments = request.env["vscreens.payment"].sudo().search([("state", "=", "confirmed"), ("payment_date", ">=", thirty)])
        activities = request.env["vscreens.calendar.activity"].sudo().search(
            [("activity_date", ">=", fields.Date.today())], order="activity_date", limit=5
        )
        return json_response({
            "companies": {"total": len(companies), "active": len(companies.filtered("is_active"))},
            "tech": {"total_screens": len(devices)},
            "revenue": {"last_30_days": sum(payments.mapped("amount"))},
            "next_activities": [{"title": a.title, "date": fields.Date.to_string(a.activity_date)} for a in activities],
            "active_promotions": request.env["vscreens.promotion"].sudo().search_count([("is_active", "=", True)]),
            "server_time": fields.Datetime.to_string(fields.Datetime.now()),
        })

    # ------------------------------------------------------------------
    # Email masivo
    # ------------------------------------------------------------------
    def _send(self, email_to, subject, body):
        if not email_to:
            return False
        request.env["mail.mail"].sudo().create({
            "subject": subject,
            "body_html": body,
            "email_to": email_to,
            "email_from": request.env["ir.config_parameter"].sudo().get_str(
                "vscreens.notification_email", "info.vscreens@inverpave.com"
            ),
        }).send()
        return True

    @http.route("/admin/crm/mass-email", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def mass_email(self, **kwargs):
        user, failure = self._master()
        if failure:
            return failure
        data = payload()
        template = None
        if data.get("template_id"):
            template = request.env["vscreens.email.template"].sudo().browse(int(data["template_id"])).exists()
        subject = data.get("subject") or (template.subject if template else "")
        body = data.get("body") or (template.body if template else "")
        if not subject or not body:
            return error(400, "Se requiere asunto y cuerpo")
        target = data.get("target", "companies")
        sent = 0
        errors = 0
        if target in ("companies", "all"):
            companies = request.env["vscreens.company"].sudo().search([("is_active", "=", True), ("email", "!=", False)])
            for company in companies:
                try:
                    rendered = {
                        "subject": subject,
                        "body": body,
                    }
                    for key, value in {
                        "{{nombre_empresa}}": company.name or "",
                        "{{contacto}}": company.contact_person or company.name or "",
                        "{{email}}": company.email or "",
                        "{{telefono}}": company.phone or "",
                        "{{plan}}": (company.plan_code or "free").capitalize(),
                        "{{fecha_vencimiento}}": fields.Date.to_string(company.valid_until.date()) if company.valid_until else "N/A",
                        "{{pantallas_activas}}": str(company.active_screens),
                        "{{max_pantallas}}": str(company.max_screens_effective),
                        "{{fecha_hoy}}": fields.Date.to_string(fields.Date.today()),
                        "{{whatsapp}}": company.whatsapp or "",
                        "{{nombre_promo}}": data.get("promo_name", ""),
                        "{{codigo_promo}}": data.get("promo_code", ""),
                        "{{descuento}}": data.get("promo_discount", ""),
                    }.items():
                        rendered["subject"] = rendered["subject"].replace(key, value)
                        rendered["body"] = rendered["body"].replace(key, value)
                    if self._send(company.email, rendered["subject"], rendered["body"]):
                        sent += 1
                except Exception:
                    errors += 1
        if target in ("leads", "all"):
            leads = request.env["crm.lead"].sudo().search([("email_from", "!=", False), ("vscreens_source_detail", "!=", False)])
            for lead in leads:
                try:
                    subj = subject.replace("{{contacto}}", lead.contact_name or "").replace("{{nombre_empresa}}", lead.partner_name or "")
                    text = body.replace("{{contacto}}", lead.contact_name or "").replace("{{nombre_empresa}}", lead.partner_name or "")
                    if self._send(lead.email_from, subj, text):
                        sent += 1
                except Exception:
                    errors += 1
        return json_response({"status": "success", "sent": sent, "errors": errors})

    @http.route("/admin/crm/send-email-company/<int:company_id>", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def send_email_company(self, company_id, **kwargs):
        user, failure = self._master()
        if failure:
            return failure
        company = request.env["vscreens.company"].sudo().browse(company_id).exists()
        if not company or not company.email:
            return error(404, "Empresa no encontrada o sin email")
        data = payload()
        template = None
        if data.get("template_id"):
            template = request.env["vscreens.email.template"].sudo().browse(int(data["template_id"])).exists()
        subject = data.get("subject") or (template.subject if template else "")
        body = data.get("body") or (template.body if template else "")
        if not subject or not body:
            return error(400, "Se requiere plantilla o asunto y cuerpo")
        extra = {
            "nombre_promo": data.get("promo_name", ""),
            "codigo_promo": data.get("promo_code", ""),
            "descuento": data.get("promo_discount", ""),
            "short_url": f"{request.env['ir.config_parameter'].sudo().get_str('vscreens.api_public_url', 'https://vscreens-api.inverpave.com')}/downloads/tv",
        }
        for key, value in extra.items():
            body = body.replace("{{" + key + "}}", value)
        for key, value in {
            "nombre_empresa": company.name or "",
            "contacto": company.contact_person or company.name or "",
            "email": company.email or "",
            "telefono": company.phone or "",
            "plan": (company.plan_code or "free").capitalize(),
            "fecha_vencimiento": fields.Date.to_string(company.valid_until.date()) if company.valid_until else "N/A",
            "pantallas_activas": str(company.active_screens),
            "max_pantallas": str(company.max_screens_effective),
            "fecha_hoy": fields.Date.to_string(fields.Date.today()),
            "whatsapp": company.whatsapp or "",
        }.items():
            subject = subject.replace("{{" + key + "}}", value)
            body = body.replace("{{" + key + "}}", value)
        self._send(company.email, subject, body)
        return json_response({"status": "success", "sent_to": company.email})
