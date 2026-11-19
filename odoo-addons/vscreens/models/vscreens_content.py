from odoo import fields, models


class VScreenSGlobalAd(models.Model):
    _name = "vscreens.global.ad"
    _description = "Publicidad global para planes free"
    _order = "write_date desc, id desc"

    name = fields.Char(default="Publicidad global")
    active = fields.Boolean(default=True)
    video_url = fields.Char(string="Video (obsoleto)")
    video_playlist = fields.Json(string="Playlist de videos", default=list)
    ticker_text = fields.Char(string="Ticker (obsoleto)")
    ticker_messages = fields.Json(string="Mensajes del ticker", default=list)
    ad_scripts = fields.Json(string="Scripts de anuncios", default=list)

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "video_url": self.video_url or "",
            "video_playlist": self.video_playlist or [],
            "ticker_text": self.ticker_text or "",
            "ticker_messages": self.ticker_messages or [],
            "ad_scripts": self.ad_scripts or [],
            "updated_at": fields.Datetime.to_string(self.write_date) if self.write_date else None,
        }


class VScreenSMenuItem(models.Model):
    _name = "vscreens.menu.item"
    _description = "Ítem de menú del cliente"
    _order = "category, name"

    company_id = fields.Many2one("vscreens.company", string="Empresa", required=True, ondelete="cascade", index=True)
    name = fields.Char(string="Nombre", required=True)
    price = fields.Float(string="Precio", default=0.0)
    category = fields.Char(string="Categoría")
    is_available = fields.Boolean(string="Disponible", default=True)

    def api_dict(self):
        self.ensure_one()
        return {
            "id": self.id,
            "company_id": self.company_id.id,
            "name": self.name,
            "price": self.price,
            "category": self.category or "",
            "is_available": self.is_available,
        }
# Nota: VScreenSEmailTemplate, VScreenSPromotion, VScreenSAffiliate y VScreenSCalendarActivity
# viven en sus archivos dedicados (vscreens_email_template.py, vscreens_promotion.py,
# vscreens_affiliate.py y vscreens_calendar_activity.py) para evitar definiciones duplicadas.
