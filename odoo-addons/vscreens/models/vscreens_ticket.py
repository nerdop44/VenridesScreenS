from odoo import api, fields, models


class VScreenSTicket(models.Model):
    _name = "vscreens.ticket"
    _description = "Ticket de soporte VScreenS"
    _inherit = ["mail.thread", "mail.activity.mixin"]
    _order = "create_date desc"

    name = fields.Char(string="Asunto", required=True)
    company_id = fields.Many2one("vscreens.company", string="Empresa", ondelete="cascade", index=True)
    user_id = fields.Many2one("res.users", string="Solicitante", ondelete="set null")
    category = fields.Selection(
        [("technical", "Técnico"), ("billing", "Facturación"), ("general", "General")],
        default="general",
        required=True,
    )
    priority = fields.Selection(
        [("low", "Baja"), ("normal", "Normal"), ("high", "Alta"), ("urgent", "Urgente")],
        default="normal",
        required=True,
    )
    status = fields.Selection(
        [("open", "Abierto"), ("in_progress", "En proceso"), ("resolved", "Resuelto"), ("closed", "Cerrado")],
        default="open",
        required=True,
        tracking=True,
    )
    description = fields.Text()
    message_ids = fields.One2many("vscreens.ticket.message", "ticket_id", string="Mensajes")

    @api.model
    def message_new(self, msg_dict, custom_values=None):
        vals = dict(custom_values or {})
        subject = msg_dict.get("subject") or "Correo entrante"
        body = msg_dict.get("body") or ""
        email_from = msg_dict.get("email_from") or ""
        user = self.env["res.users"].sudo().search([("login", "=", email_from)], limit=1)
        company = user.vscreens_company_id if user else False
        vals.update({
            "name": subject,
            "description": body,
            "category": "general",
            "priority": "normal",
            "status": "open",
            "user_id": user.id if user else False,
            "company_id": company.id if company else False,
        })
        return self.create(vals)

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "subject": self.name,
            "category": self.category,
            "priority": self.priority,
            "status": self.status,
            "created_at": fields.Datetime.to_string(self.create_date) if self.create_date else None,
            "updated_at": fields.Datetime.to_string(self.write_date) if self.write_date else None,
            "user_email": self.user_id.login if self.user_id else "Unknown",
        }


class VScreenSTicketMessage(models.Model):
    _name = "vscreens.ticket.message"
    _description = "Mensaje de ticket"
    _order = "create_date asc, id asc"

    ticket_id = fields.Many2one("vscreens.ticket", string="Ticket", required=True, ondelete="cascade")
    sender_id = fields.Many2one("res.users", string="Remitente", ondelete="set null")
    body = fields.Text(string="Mensaje", required=True)
    is_internal = fields.Boolean(default=False)

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "body": self.body,
            "created_at": fields.Datetime.to_string(self.create_date) if self.create_date else None,
            "sender_email": self.sender_id.login if self.sender_id else "Sistema",
            "is_staff": bool(self.sender_id and self.sender_id.has_group("vscreens.group_vscreens_master")),
        }
