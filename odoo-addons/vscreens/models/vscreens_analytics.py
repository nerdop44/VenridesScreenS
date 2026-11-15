from odoo import fields, models


class VScreenSAnalyticsVisit(models.Model):
    _name = "vscreens.analytics.visit"
    _description = "Visita analítica del sitio"
    _order = "visit_date desc, id desc"

    page = fields.Char(default="/", index=True)
    referrer = fields.Char()
    device = fields.Char()
    country = fields.Char(default="unknown")
    ip_hash = fields.Char(index=True)
    user_agent = fields.Text()
    visit_date = fields.Datetime(default=fields.Datetime.now, index=True)

    def api_dict(self):
        self.ensure_one()
        return {
            "page": self.page,
            "referrer": self.referrer or "",
            "device": self.device or "",
            "country": self.country or "",
            "timestamp": fields.Datetime.to_string(self.visit_date) if self.visit_date else None,
        }


class VScreenSBenrySession(models.Model):
    _name = "vscreens.benry.session"
    _description = "Sesión de chat de Benry"
    _order = "last_message_at desc"

    session_id = fields.Char(required=True, index=True)
    company_id = fields.Many2one("vscreens.company", string="Empresa", ondelete="set null")
    last_message_at = fields.Datetime(default=fields.Datetime.now)
    summary = fields.Text()
    needs_handoff = fields.Boolean(default=False)
    lead_type = fields.Char()


class VScreenSBenryMessage(models.Model):
    _name = "vscreens.benry.message"
    _description = "Mensaje de Benry"
    _order = "create_date asc, id asc"

    session_id = fields.Char(required=True, index=True)
    role = fields.Selection([("user", "Usuario"), ("assistant", "Benry")], required=True)
    body = fields.Text(required=True)


class VScreenSSeoConfig(models.Model):
    _name = "vscreens.seo.config"
    _description = "Configuración SEO de la Landing"
    _order = "id desc"
    _rec_name = "page"

    page = fields.Char(string="Página", required=True, default="/")
    meta_title = fields.Char(string="Título Meta (SEO)")
    meta_description = fields.Char(string="Descripción Meta (SEO)")
    meta_keywords = fields.Char(string="Palabras Clave (SEO)")
    canonical_url = fields.Char(string="URL Canónica")
    og_title = fields.Char(string="Título Open Graph")
    og_description = fields.Char(string="Descripción Open Graph")
    og_image = fields.Binary(string="Imagen Open Graph", attachment=True)
    google_analytics_id = fields.Char(string="ID de Google Analytics")
    google_search_console = fields.Char(string="Google Search Console")
    facebook_pixel = fields.Char(string="Facebook Pixel ID")

    def api_dict(self):
        self.ensure_one()
        return {
            "page": self.page,
            "meta_title": self.meta_title or "",
            "meta_description": self.meta_description or "",
            "meta_keywords": self.meta_keywords or "",
            "canonical_url": self.canonical_url or "",
            "og_title": self.og_title or "",
            "og_description": self.og_description or "",
            "google_analytics_id": self.google_analytics_id or "",
            "google_search_console": self.google_search_console or "",
            "facebook_pixel": self.facebook_pixel or "",
        }
