# -*- coding: utf-8 -*-
from odoo import api, fields, models


class VscreensTrackingLink(models.Model):
    _name = "vscreens.tracking.link"
    _description = "Enlace de seguimiento (tracking) VScreenS"
    _order = "created_at desc, id desc"
    _rec_name = "name"

    name = fields.Char(string="Nombre", required=True)
    url = fields.Char(string="URL de destino", required=True, help="URL a la que redirige el enlace")
    short_code = fields.Char(
        string="Código corto",
        required=True,
        index=True,
        help="Código corto para el enlace de seguimiento (ej: bf2026)",
    )
    promotion_id = fields.Many2one(
        "vscreens.promotion",
        string="Promoción asociada",
        ondelete="set null",
        help="Promoción vinculada a este enlace de seguimiento",
    )
    affiliate_id = fields.Many2one(
        "vscreens.affiliate",
        string="Afiliado asociado",
        ondelete="set null",
        help="Afiliado propietario de este enlace de seguimiento",
    )
    clicks = fields.Integer(string="Clics", default=0, readonly=True)
    conversions = fields.Integer(string="Conversiones", default=0, readonly=True)
    is_active = fields.Boolean(string="Activo", default=True)
    created_at = fields.Datetime(string="Creado el", default=fields.Datetime.now, readonly=True)

    _short_code_uniq = models.Constraint("UNIQUE(short_code)", "El código corto debe ser único.")

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "name": self.name or "",
            "url": self.url or "",
            "short_code": self.short_code or "",
            "promotion_id": self.promotion_id.id if self.promotion_id else None,
            "promotion_name": self.promotion_id.name if self.promotion_id else "",
            "affiliate_id": self.affiliate_id.id if self.affiliate_id else None,
            "affiliate_name": self.affiliate_id.name if self.affiliate_id else "",
            "clicks": self.clicks,
            "conversions": self.conversions,
            "is_active": self.is_active,
            "created_at": fields.Datetime.to_string(self.created_at) if self.created_at else None,
        }

    def action_register_click(self):
        """Registra un clic en el enlace de seguimiento."""
        self.ensure_one()
        self.sudo().write({"clicks": self.clicks + 1})
        return True

    def action_register_conversion(self):
        """Registra una conversión en el enlace de seguimiento."""
        self.ensure_one()
        self.sudo().write({"conversions": self.conversions + 1})
        return True
