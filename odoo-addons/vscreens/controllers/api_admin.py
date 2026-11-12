from odoo import fields, http
from odoo.http import request

from .api_common import (
    bearer_user,
    can_access_company,
    company_of,
    error,
    is_master,
    json_response,
    payload,
    role_of,
)


class VScreenSAdminController(http.Controller):

    # ------------------------------------------------------------------
    # Pagos
    # ------------------------------------------------------------------
    @http.route("/admin/payments/", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def payments(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        domain = [] if is_master(user) else [("company_id", "=", user.vscreens_company_id.id)]
        payments = request.env["vscreens.payment"].sudo().search(domain, order="payment_date desc")
        return json_response([payment.api_dict() for payment in payments])

    @http.route("/admin/payments/<int:company_id>", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def company_payments(self, company_id, **kwargs):
        user = bearer_user()
        company = request.env["vscreens.company"].sudo().browse(company_id).exists()
        if not user or not company:
            return error(404, "Empresa no encontrada")
        if not can_access_company(user, company):
            return error(403, "No autorizado")
        return json_response([payment.api_dict() for payment in company.payment_ids.sorted("payment_date", reverse=True)])

    @http.route("/admin/payments/create", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def create_payment(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        data = payload()
        company = request.env["vscreens.company"].sudo().browse(int(data.get("company_id") or 0)).exists()
        if not company:
            return error(400, "Empresa requerida")
        if not can_access_company(user, company):
            return error(403, "No autorizado")
        if role_of(user) == "operador_empresa":
            return error(403, "No autorizado")
        currency = request.env["res.currency"].sudo().search([("name", "=", data.get("currency") or "USD")], limit=1)
        payment = request.env["vscreens.payment"].sudo().create({
            "company_id": company.id,
            "amount": float(data.get("amount") or 0),
            "currency_id": (currency or request.env.company.currency_id).id,
            "payment_method": data.get("payment_method") or "",
            "description": data.get("description") or "",
            "payment_date": fields.Datetime.to_datetime(data.get("payment_date")) if data.get("payment_date") else fields.Datetime.now(),
        })
        return json_response(payment.api_dict(), status=201)

    @http.route("/admin/payments/<int:payment_id>", type="http", auth="public", methods=["PATCH", "POST", "DELETE", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def payment_detail(self, payment_id, **kwargs):
        user = bearer_user()
        payment = request.env["vscreens.payment"].sudo().browse(payment_id).exists()
        if not user or not payment:
            return error(404, "Pago no encontrado")
        if not is_master(user):
            return error(403, "No autorizado")
        if request.httprequest.method == "DELETE":
            payment.sudo().unlink()
            return json_response({"message": "Pago eliminado correctamente"})
        data = payload()
        vals = {}
        if "amount" in data:
            vals["amount"] = float(data["amount"])
        if "payment_method" in data:
            vals["payment_method"] = data["payment_method"]
        if "description" in data:
            vals["description"] = data["description"]
        if vals:
            payment.sudo().write(vals)
        return json_response({"message": "Pago actualizado correctamente"})

    # ------------------------------------------------------------------
    # Publicidad global
    # ------------------------------------------------------------------
    @http.route("/admin/global-ad", type="http", auth="public", methods=["GET", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def global_ad(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        ad = request.env["vscreens.global.ad"].sudo().search([], order="write_date desc", limit=1)
        if request.httprequest.method == "GET":
            return json_response(ad.api_dict() if ad else {
                "video_url": "", "video_playlist": [], "ticker_text": "", "ticker_messages": [], "ad_scripts": []
            })
        if not is_master(user):
            return error(403, "No autorizado")
        data = payload()
        vals = {
            "video_url": data.get("video_url") or "",
            "video_playlist": data.get("video_playlist") or [],
            "ticker_text": data.get("ticker_text") or "",
            "ticker_messages": data.get("ticker_messages") or [],
            "ad_scripts": data.get("ad_scripts") or [],
        }
        if ad:
            ad.sudo().write(vals)
        else:
            ad = request.env["vscreens.global.ad"].sudo().create(vals)
        return json_response(ad.api_dict())

    # ------------------------------------------------------------------
    # Estadísticas
    # ------------------------------------------------------------------
    @http.route("/admin/stats/overview", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def stats(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        if is_master(user):
            companies = request.env["vscreens.company"].sudo().search([])
            devices = request.env["vscreens.device"].sudo().search([])
            revenue = sum(request.env["vscreens.payment"].sudo().search([("state", "=", "confirmed")]).mapped("amount"))
        else:
            companies = user.vscreens_company_id
            devices = companies.device_ids
            revenue = sum(companies.payment_ids.filtered(lambda p: p.state == "confirmed").mapped("amount"))
        return json_response({
            "total_companies": len(companies),
            "active_companies": len(companies.filtered("is_active")),
            "total_screens": len(devices),
            "monthly_revenue": revenue,
        })

    # ------------------------------------------------------------------
    # Helpdesk
    # ------------------------------------------------------------------
    @http.route("/admin/helpdesk/tickets", type="http", auth="public", methods=["GET", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def tickets(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        if request.httprequest.method == "GET":
            domain = [] if is_master(user) else [
                "|", ("user_id", "=", user.id), ("company_id", "=", user.vscreens_company_id.id)
            ]
            tickets = request.env["vscreens.ticket"].sudo().search(domain, order="write_date desc")
            return json_response([ticket.api_dict() for ticket in tickets])
        data = payload()
        ticket = request.env["vscreens.ticket"].sudo().create({
            "name": data.get("subject") or "Ticket",
            "category": data.get("category") or "general",
            "priority": data.get("priority") or "normal",
            "status": "open",
            "company_id": user.vscreens_company_id.id if user.vscreens_company_id else False,
            "user_id": user.id,
            "description": data.get("initial_message") or "",
        })
        request.env["vscreens.ticket.message"].sudo().create({
            "ticket_id": ticket.id,
            "sender_id": user.id,
            "body": data.get("initial_message") or "",
        })
        return json_response({"id": ticket.id, "message": "Ticket creado exitosamente"}, status=201)

    @http.route("/admin/helpdesk/tickets/<int:ticket_id>", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def ticket_detail(self, ticket_id, **kwargs):
        user = bearer_user()
        ticket = request.env["vscreens.ticket"].sudo().browse(ticket_id).exists()
        if not user or not ticket:
            return error(404, "Ticket no encontrado")
        if not is_master(user) and ticket.user_id.id != user.id and ticket.company_id.id != user.vscreens_company_id.id:
            return error(403, "No tiene permiso para ver este ticket")
        data = ticket.api_dict()
        data["messages"] = [message.api_dict() for message in ticket.vscreens_message_ids]
        return json_response(data)

    @http.route("/admin/helpdesk/tickets/<int:ticket_id>/reply", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def ticket_reply(self, ticket_id, **kwargs):
        user = bearer_user()
        ticket = request.env["vscreens.ticket"].sudo().browse(ticket_id).exists()
        if not user or not ticket:
            return error(404, "Ticket no encontrado")
        if not is_master(user) and ticket.user_id.id != user.id and ticket.company_id.id != user.vscreens_company_id.id:
            return error(403, "No tiene permiso para responder a este ticket")
        body = (payload().get("body") or "").strip()
        if not body:
            return error(400, "Mensaje requerido")
        request.env["vscreens.ticket.message"].sudo().create({
            "ticket_id": ticket.id,
            "sender_id": user.id,
            "body": body,
        })
        if is_master(user) and ticket.status == "open":
            ticket.sudo().write({"status": "in_progress"})
        return json_response({"message": "Respuesta enviada"})

    @http.route("/admin/helpdesk/tickets/<int:ticket_id>/status", type="http", auth="public", methods=["PATCH", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def ticket_status(self, ticket_id, **kwargs):
        user = bearer_user()
        ticket = request.env["vscreens.ticket"].sudo().browse(ticket_id).exists()
        if not user or not ticket:
            return error(404, "Ticket no encontrado")
        if not is_master(user):
            return error(403, "No autorizado")
        status = request.httprequest.args.get("status") or payload().get("status")
        if status not in ("open", "in_progress", "resolved", "closed"):
            return error(400, "Estado inválido")
        ticket.sudo().write({"status": status})
        return json_response({"message": f"Estado actualizado a {status}"})

    # ------------------------------------------------------------------
    # Mensajería / chat
    # ------------------------------------------------------------------
    @http.route("/admin/messages/inbox", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def inbox(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        domain = [("receiver_id", "=", user.id)]
        if is_master(user):
            domain = []
        messages = request.env["vscreens.message"].sudo().search(domain, order="create_date desc")
        return json_response([message.api_dict() for message in messages])

    @http.route("/admin/messages/<int:message_id>/read", type="http", auth="public", methods=["PATCH", "POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def message_read(self, message_id, **kwargs):
        user = bearer_user()
        message = request.env["vscreens.message"].sudo().browse(message_id).exists()
        if not user or not message:
            return error(404, "Mensaje no encontrado")
        if not is_master(user) and message.receiver_id.id != user.id and message.company_id.id != user.vscreens_company_id.id:
            return error(403, "No autorizado")
        message.sudo().write({"is_read": True})
        return json_response({"status": "ok"})

    @http.route("/admin/chat/conversations", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def chat_conversations(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        threads = request.env["vscreens.chat.thread"].sudo().search([
            "|",
            "&", ("participant_1_id", "=", user.id), ("is_hidden_by_1", "=", False),
            "&", ("participant_2_id", "=", user.id), ("is_hidden_by_2", "=", False),
        ], order="last_message_at desc")
        result = []
        for thread in threads:
            partner = thread.participant_2_id if thread.participant_1_id.id == user.id else thread.participant_1_id
            unread = request.env["vscreens.message"].sudo().search_count([
                ("sender_id", "=", partner.id), ("receiver_id", "=", user.id), ("is_read", "=", False)
            ])
            result.append({
                "partner": {"id": partner.id, "username": partner.login, "role": partner.vscreens_role},
                "last_message": thread.last_subject or "S/M",
                "last_message_at": fields.Datetime.to_string(thread.last_message_at) if thread.last_message_at else None,
                "unread_count": unread,
            })
        # Sesiones de invitado (Benry)
        guest_messages = request.env["vscreens.message"].sudo().search([
            ("receiver_id", "=", user.id), ("session_id", "!=", False)
        ], order="create_date desc")
        seen = set()
        for message in guest_messages:
            if message.session_id in seen:
                continue
            seen.add(message.session_id)
            result.append({
                "partner": {
                    "id": f"guest_{message.session_id}",
                    "username": f"GUEST: {message.session_id[:8]}",
                    "role": "guest",
                    "is_guest": True,
                    "session_id": message.session_id,
                },
                "last_message": (message.body or "")[:50],
                "last_message_at": fields.Datetime.to_string(message.create_date) if message.create_date else None,
                "unread_count": 0 if message.is_read else 1,
            })
        return json_response(result)

    @http.route("/admin/chat/messages/<string:partner_id>", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def chat_messages(self, partner_id, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        if partner_id.startswith("guest_"):
            session_id = partner_id.replace("guest_", "")
            domain = [("session_id", "=", session_id)]
            if not is_master(user):
                domain.append(("receiver_id", "=", user.id))
            messages = request.env["vscreens.message"].sudo().search(domain, order="create_date asc")
        else:
            try:
                pid = int(partner_id)
            except ValueError:
                return error(400, "ID inválido")
            partner = request.env["res.users"].sudo().browse(pid).exists()
            if not partner:
                return error(404, "Destinatario no encontrado")
            if not is_master(user) and partner.vscreens_company_id.id != user.vscreens_company_id.id:
                return error(403, "No autorizado")
            messages = request.env["vscreens.message"].sudo().search([
                ("is_alert", "=", False),
                "|",
                "&", ("sender_id", "=", user.id), ("receiver_id", "=", pid),
                "&", ("sender_id", "=", pid), ("receiver_id", "=", user.id),
            ], order="create_date asc")
            messages.filtered(lambda m: m.receiver_id.id == user.id).sudo().write({"is_read": True})
        return json_response([message.api_dict() for message in messages])

    @http.route("/admin/chat/send", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def chat_send(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        data = payload()
        body = (data.get("body") or "").strip()
        receiver_raw = str(data.get("receiver_id") or "")
        if not body or not receiver_raw:
            return error(400, "Destinatario y mensaje son obligatorios")
        session_id = None
        receiver_id = None
        if receiver_raw.startswith("guest_"):
            session_id = receiver_raw.replace("guest_", "")
        else:
            try:
                receiver_id = int(receiver_raw)
            except ValueError:
                return error(400, "ID de destinatario inválido")
            receiver = request.env["res.users"].sudo().browse(receiver_id).exists()
            if not receiver:
                return error(404, "Destinatario no encontrado")
            if not is_master(user) and receiver.vscreens_company_id.id != user.vscreens_company_id.id:
                return error(403, "No autorizado")
            blocked = request.env["vscreens.blocked.user"].sudo().search([
                "|",
                "&", ("blocker_id", "=", user.id), ("blocked_id", "=", receiver_id),
                "&", ("blocker_id", "=", receiver_id), ("blocked_id", "=", user.id),
            ], limit=1)
            if blocked:
                return error(403, "Comunicación bloqueada entre estos usuarios")
            p1, p2 = sorted([user.id, receiver_id])
            thread = request.env["vscreens.chat.thread"].sudo().search([
                ("participant_1_id", "=", p1), ("participant_2_id", "=", p2)
            ], limit=1)
            if not thread:
                thread = request.env["vscreens.chat.thread"].sudo().create({
                    "participant_1_id": p1,
                    "participant_2_id": p2,
                    "last_message_at": fields.Datetime.now(),
                    "last_subject": body[:100],
                })
            else:
                sender_is_p1 = thread.participant_1_id.id == user.id
                thread.sudo().write({
                    "last_message_at": fields.Datetime.now(),
                    "last_subject": body[:100],
                    "is_read_by_1": sender_is_p1,
                    "is_read_by_2": not sender_is_p1,
                    "is_hidden_by_1": False,
                    "is_hidden_by_2": False,
                })
        request.env["vscreens.message"].sudo().create({
            "sender_id": user.id,
            "receiver_id": receiver_id,
            "session_id": session_id,
            "subject": "Chat Interno" if not session_id else "Soporte Benry",
            "body": body,
            "is_alert": False,
        })
        return json_response({"status": "success"})

    @http.route("/admin/chat/unread-count", type="http", auth="public", methods=["GET", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def chat_unread(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        count = request.env["vscreens.chat.thread"].sudo().search_count([
            "|",
            "&", ("participant_1_id", "=", user.id), ("is_read_by_1", "=", False), ("is_hidden_by_1", "=", False),
            "&", ("participant_2_id", "=", user.id), ("is_read_by_2", "=", False), ("is_hidden_by_2", "=", False),
        ])
        return json_response({"unread_count": count})

    @http.route("/admin/chat/block", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def chat_block(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        blocked_id = request.httprequest.args.get("blocked_id") or payload().get("blocked_id")
        try:
            blocked_id = int(blocked_id)
        except (TypeError, ValueError):
            return error(400, "ID inválido")
        if blocked_id == user.id:
            return error(400, "No te puedes bloquear a ti mismo")
        blocked_user = request.env["res.users"].sudo().browse(blocked_id).exists()
        if not blocked_user:
            return error(404, "Usuario no encontrado")
        if not is_master(user) and blocked_user.vscreens_company_id.id != user.vscreens_company_id.id:
            return error(403, "No autorizado")
        existing = request.env["vscreens.blocked.user"].sudo().search([
            ("blocker_id", "=", user.id), ("blocked_id", "=", blocked_id)
        ], limit=1)
        if not existing:
            request.env["vscreens.blocked.user"].sudo().create({
                "blocker_id": user.id, "blocked_id": blocked_id, "reason": payload().get("reason") or ""
            })
        return json_response({"message": "Usuario bloqueado"})

    @http.route("/admin/chat/unblock", type="http", auth="public", methods=["POST", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def chat_unblock(self, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        blocked_id = request.httprequest.args.get("blocked_id") or payload().get("blocked_id")
        try:
            blocked_id = int(blocked_id)
        except (TypeError, ValueError):
            return error(400, "ID inválido")
        block = request.env["vscreens.blocked.user"].sudo().search([
            ("blocker_id", "=", user.id), ("blocked_id", "=", blocked_id)
        ], limit=1)
        if block:
            block.sudo().unlink()
        return json_response({"message": "Usuario desbloqueado"})

    @http.route("/admin/chat/conversation/<int:partner_id>", type="http", auth="public", methods=["DELETE", "OPTIONS"], csrf=False, cors="*", save_session=False)
    def chat_delete(self, partner_id, **kwargs):
        user = bearer_user()
        if not user:
            return error(401, "No autenticado")
        p1, p2 = sorted([user.id, partner_id])
        thread = request.env["vscreens.chat.thread"].sudo().search([
            ("participant_1_id", "=", p1), ("participant_2_id", "=", p2)
        ], limit=1)
        if thread:
            if thread.participant_1_id.id == user.id:
                thread.sudo().write({"is_hidden_by_1": True})
            else:
                thread.sudo().write({"is_hidden_by_2": True})
        return json_response({"message": "Conversación eliminada (vista local)"})
