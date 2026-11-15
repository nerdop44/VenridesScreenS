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
    # Barra Inferior
    bottom_bar_bg = fields.Char(string="Color de Fondo Barra Inferior", default="#0a0e1a")
    bottom_bar_text = fields.Char(string="Color de Texto Barra Inferior", default="#ffffff")
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
            "bottom_bar_bg": self.bottom_bar_bg,
            "bottom_bar_text": self.bottom_bar_text,
            "show_bcv": self.show_bcv,
            "bcv_color": self.bcv_color,
            "bcv_font": self.bcv_font,
        }
