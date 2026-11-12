from odoo import fields, models


class VScreenSMessage(models.Model):
    _name = "vscreens.message"
    _description = "Mensaje, alerta o chat de VScreenS"
    _order = "create_date desc, id desc"

    sender_id = fields.Many2one("res.users", string="Remitente", ondelete="set null")
    receiver_id = fields.Many2one("res.users", string="Destinatario", ondelete="set null")
    company_id = fields.Many2one("vscreens.company", string="Empresa", ondelete="cascade", index=True)
    subject = fields.Char(string="Asunto")
    body = fields.Text(string="Mensaje")
    attachment_url = fields.Char(string="Adjunto")
    is_read = fields.Boolean(default=False)
    is_alert = fields.Boolean(string="Alerta en vivo", default=False)
    alert_duration = fields.Integer(string="Duración (s)", default=15)
    session_id = fields.Char(string="Sesión", index=True)

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "sender_id": self.sender_id.id if self.sender_id else None,
            "receiver_id": self.receiver_id.id if self.receiver_id else None,
            "company_id": self.company_id.id if self.company_id else None,
            "subject": self.subject or "",
            "body": self.body or "",
            "attachment_url": self.attachment_url or "",
            "is_read": self.is_read,
            "is_alert": self.is_alert,
            "alert_duration": self.alert_duration,
            "session_id": self.session_id or "",
            "created_at": fields.Datetime.to_string(self.create_date) if self.create_date else None,
        }


class VScreenSChatThread(models.Model):
    _name = "vscreens.chat.thread"
    _description = "Conversación de chat interno"
    _order = "last_message_at desc, id desc"

    participant_1_id = fields.Many2one("res.users", string="Participante 1", required=True, ondelete="cascade")
    participant_2_id = fields.Many2one("res.users", string="Participante 2", required=True, ondelete="cascade")
    last_message_at = fields.Datetime(default=fields.Datetime.now)
    last_subject = fields.Char()
    is_read_by_1 = fields.Boolean(default=True)
    is_read_by_2 = fields.Boolean(default=True)
    is_hidden_by_1 = fields.Boolean(default=False)
    is_hidden_by_2 = fields.Boolean(default=False)


class VScreenSBlockedUser(models.Model):
    _name = "vscreens.blocked.user"
    _description = "Usuario bloqueado en el chat"
    _order = "create_date desc"

    blocker_id = fields.Many2one("res.users", string="Bloqueador", required=True, ondelete="cascade")
    blocked_id = fields.Many2one("res.users", string="Bloqueado", required=True, ondelete="cascade")
    reason = fields.Char()
