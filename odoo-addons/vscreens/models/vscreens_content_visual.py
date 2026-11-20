# -*- coding: utf-8 -*-
# Licensed under the LGPLv3 - VScreenS - Localización Venezuela (LocVe)

from odoo import api, fields, models
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class VscreensPlaylistItem(models.Model):
    _name = "vscreens.playlist.item"
    _description = "Ítem de Playlist VScreenS"
    _order = "sequence, id"
    _rec_name = "title"

    company_id = fields.Many2one(
        "vscreens.company",
        string="Empresa",
        required=True,
        ondelete="cascade",
    )
    sequence = fields.Integer(string="Secuencia", default=10)
    title = fields.Char(string="Título", required=True, help="Título del video")
    url = fields.Char(string="URL de YouTube", required=True, help="https://www.youtube.com/watch?v=...")
    youtube_id = fields.Char(string="ID de YouTube", compute="_compute_youtube_id", store=True)
    is_active = fields.Boolean(string="Activo", default=True)

    @api.depends("url")
    def _compute_youtube_id(self):
        import re
        for rec in self:
            if rec.url:
                match = re.search(r'(?:youtube\.com\/(?:[^\/]+\/.+\/|(?:v|e(?:mbed)?|shorts|live)\/|.*[?&]v=)|youtu\.be\/)([^"&?\/\s]{11})', rec.url)
                rec.youtube_id = match.group(1) if match else False
            else:
                rec.youtube_id = False

    @api.constrains("url")
    def _check_url(self):
        for rec in self:
            if rec.url and not rec.youtube_id:
                raise ValidationError("La URL de YouTube no es válida. Ejemplo: https://www.youtube.com/watch?v=LXb3EKWsInQ")


class VscreensScheduledVideoItem(models.Model):
    _name = "vscreens.scheduled.video.item"
    _description = "Video Programado VScreenS"
    _order = "sequence, start_datetime"
    _rec_name = "title"

    company_id = fields.Many2one(
        "vscreens.company",
        string="Empresa",
        required=True,
        ondelete="cascade",
    )
    sequence = fields.Integer(string="Secuencia", default=10)
    title = fields.Char(string="Título", required=True)
    url = fields.Char(string="URL de YouTube", required=True)
    youtube_id = fields.Char(string="ID de YouTube", compute="_compute_youtube_id", store=True)
    start_datetime = fields.Datetime(string="Fecha y Hora de Inicio", required=True)
    end_datetime = fields.Datetime(string="Fecha y Hora de Fin")
    duration = fields.Integer(string="Duración (segundos)", default=300)
    is_active = fields.Boolean(string="Activo", default=True)

    @api.depends("url")
    def _compute_youtube_id(self):
        import re
        for rec in self:
            if rec.url:
                match = re.search(r'(?:youtube\.com\/(?:[^\/]+\/.+\/|(?:v|e(?:mbed)?|shorts|live)\/|.*[?&]v=)|youtu\.be\/)([^"&?\/\s]{11})', rec.url)
                rec.youtube_id = match.group(1) if match else False
            else:
                rec.youtube_id = False


class VscreensSidebarItem(models.Model):
    _name = "vscreens.sidebar.item"
    _description = "Ítem de Barra Lateral VScreenS"
    _order = "sequence, id"
    _rec_name = "label"

    company_id = fields.Many2one(
        "vscreens.company",
        string="Empresa",
        required=True,
        ondelete="cascade",
    )
    sequence = fields.Integer(string="Secuencia", default=10)
    label = fields.Char(string="Etiqueta", required=True)
    value = fields.Char(string="Valor", required=True, help="Texto o valor a mostrar")
    icon = fields.Char(string="Icono", default="fa-tv", help="Clase de icono FontAwesome")
    color = fields.Char(string="Color", default="#ffffff", help="Color en formato hex")
    image_url = fields.Char(string="URL de Imagen", help="Imagen opcional junto al texto")
    image = fields.Binary(string="Imagen", attachment=True)
    is_active = fields.Boolean(string="Activo", default=True)


class VscreensBottomBarItem(models.Model):
    _name = "vscreens.bottom.bar.item"
    _description = "Ítem de Barra Inferior VScreenS"
    _order = "sequence, id"
    _rec_name = "label"

    company_id = fields.Many2one(
        "vscreens.company",
        string="Empresa",
        required=True,
        ondelete="cascade",
    )
    sequence = fields.Integer(string="Secuencia", default=10)
    label = fields.Char(string="Etiqueta", required=True)
    value = fields.Char(string="Valor", required=True)
    color = fields.Char(string="Color", default="#c8ff00", help="Color en formato hex")
    is_active = fields.Boolean(string="Activo", default=True)


class VscreensDesignSettings(models.Model):
    _name = "vscreens.design.settings"
    _description = "Ajustes de Diseño VScreenS"
    _order = "id"
    _rec_name = "company_id"

    company_id = fields.Many2one(
        "vscreens.company",
        string="Empresa",
        required=True,
        ondelete="cascade",
    )
    # Título
    title_font = fields.Selection(
        [("inherit", "Heredar"), ("'Inter', sans-serif", "Inter"), ("'Roboto', sans-serif", "Roboto"), ("'Outfit', sans-serif", "Outfit"), ("serif", "Serif"), ("monospace", "Monospace")],
        string="Fuente del Título",
        default="inherit",
    )
    title_color = fields.Char(string="Color del Título", default="#ffffff")
    title_size = fields.Char(string="Tamaño del Título", default="1.2rem")
    title_weight = fields.Selection(
        [("normal", "Normal"), ("bold", "Negrita"), ("900", "Grueso")],
        string="Grosor",
        default="bold",
    )
    # Barra Lateral
    sidebar_width = fields.Integer(string="Ancho de Barra Lateral (%)", default=22)
    sidebar_effect = fields.Selection(
        [("none", "Ninguno"), ("glass_3d", "Cristal 3D"), ("neon_glow", "Neón")],
        string="Efecto de Barra Lateral",
        default="none",
    )
    sidebar_bg = fields.Char(string="Color de Fondo", default="#1e293b")
    sidebar_text = fields.Char(string="Color de Texto", default="#ffffff")
    sidebar_animation = fields.Selection(
        [
            ("slide_up", "Deslizar Arriba"),
            ("fade", "Desvanecer (Fade)"),
            ("slide_left", "Deslizar Izquierda"),
            ("zoom", "Zoom Suave"),
            ("none", "Sin Animación"),
        ],
        string="Animación de Bloques",
        default="slide_up",
    )
    sidebar_font_scale = fields.Selection(
        [("compact", "Compacta"), ("normal", "Normal"), ("large", "Grande")],
        string="Tamaño de Fuente en Bloques",
        default="normal",
    )
    side_subtitle = fields.Char(
        string="Subtítulo bajo Nombre",
        default="PANTALLAS PUBLI-INTELIGENTES",
    )
    show_side_footer = fields.Boolean(string="Mostrar Pie Lateral", default=True)
    side_footer_text = fields.Char(
        string="Texto Pie Lateral",
        default="VScreenS · Señalización inteligente",
    )
    side_footer_animation = fields.Selection(
        [
            ("marquee", "Desplazamiento (Marquesina)"),
            ("pulse", "Brillo Suave"),
            ("fade_slide", "Entrada Suave"),
            ("none", "Fijo"),
        ],
        string="Animación Pie Lateral",
        default="marquee",
    )
    show_card_frame = fields.Boolean(string="Mostrar Marco en Bloques", default=True)
    show_slide_counter = fields.Boolean(string="Mostrar Contador (01/03)", default=False)
    show_side_menu = fields.Boolean(string="Mostrar Menú / Precios", default=True)
    side_menu_animation = fields.Selection(
        [
            ("static", "Lista Fija"),
            ("rotate", "Rotar con Animación"),
            ("marquee_vertical", "Desplazamiento Vertical"),
        ],
        string="Presentación Menú / Precios",
        default="rotate",
    )
    safety_margin = fields.Float(string="Margen Overscan (%)", default=2.0)
    show_side_clock = fields.Boolean(string="Reloj en Barra Lateral", default=False)
    # Barra Inferior y Video
    bottom_bar_bg = fields.Char(string="Color de Fondo Barra Inferior", default="#0a0e1a")
    bottom_bar_text = fields.Char(string="Color de Texto Barra Inferior", default="#ffffff")
    show_bottom_clock = fields.Boolean(string="Reloj/Fecha en Barra Inferior", default=True)
    show_topbar_date = fields.Boolean(string="Fecha en Área de Video", default=True)
    show_live_badge = fields.Boolean(string="Badge EN VIVO", default=True)
    show_social_in_ticker = fields.Boolean(string="Redes en Marquesina", default=True)
    # BCV
    show_bcv = fields.Boolean(string="Mostrar Tasa BCV", default=True)
    bcv_color = fields.Char(string="Color BCV", default="#10b981")
    bcv_font = fields.Char(string="Fuente BCV", default="inherit")

    _company_uniq = models.Constraint(
        "UNIQUE(company_id)", "Ya existe un ajuste de diseño para esta empresa."
    )

    def get_design_dict(self):
        self.ensure_one()
        return {
            "name_font": self.title_font,
            "name_color": self.title_color,
            "name_size": self.title_size,
            "name_weight": self.title_weight,
            "sidebar_width": self.sidebar_width,
            "sidebar_effect": self.sidebar_effect,
            "sidebar_bg": self.sidebar_bg,
            "sidebar_text": self.sidebar_text,
            "sidebar_animation": self.sidebar_animation or "slide_up",
            "sidebar_font_scale": self.sidebar_font_scale or "normal",
            "side_subtitle": self.side_subtitle if self.side_subtitle is not False else "",
            "show_side_footer": self.show_side_footer,
            "side_footer_text": self.side_footer_text or "",
            "side_footer_animation": self.side_footer_animation or "marquee",
            "show_card_frame": self.show_card_frame,
            "show_slide_counter": self.show_slide_counter,
            "show_side_menu": self.show_side_menu,
            "side_menu_animation": self.side_menu_animation or "rotate",
            "safety_margin": self.safety_margin if self.safety_margin is not False else 2.0,
            "show_side_clock": self.show_side_clock,
            "bottom_bar_bg": self.bottom_bar_bg,
            "bottom_bar_text": self.bottom_bar_text,
            "show_bottom_clock": self.show_bottom_clock,
            "show_topbar_date": self.show_topbar_date,
            "show_live_badge": self.show_live_badge,
            "show_social_in_ticker": self.show_social_in_ticker,
            "show_bcv": self.show_bcv,
            "bcv_color": self.bcv_color,
            "bcv_font": self.bcv_font,
        }


class VscreensOdooRemoteProduct(models.Model):
    _name = "vscreens.odoo.remote.product"
    _description = "Producto importado desde Odoo externo"
    _order = "selected desc, name, id"

    company_id = fields.Many2one(
        "vscreens.company",
        string="Empresa",
        required=True,
        ondelete="cascade",
    )
    selected = fields.Boolean(string="Mostrar en TV", default=False)
    remote_id = fields.Integer(string="ID Remoto", readonly=True)
    name = fields.Char(string="Producto", required=True)
    list_price = fields.Float(string="Precio")
    currency_symbol = fields.Char(string="Moneda", default="$")
    image_128 = fields.Binary(string="Foto", attachment=False)
