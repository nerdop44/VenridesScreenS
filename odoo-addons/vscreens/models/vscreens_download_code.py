# -*- coding: utf-8 -*-
# Licensed under the LGPLv3 - VScreenS - Localización Venezuela (LocVe)
"""Códigos cortos de descarga para la app de TV (y móvil)."""

from datetime import timedelta
import logging
import re
import secrets

from odoo import api, fields, models

_logger = logging.getLogger(__name__)

CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _new_code():
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))


class VscreensDownloadCode(models.Model):
    _name = "vscreens.download.code"
    _description = "Código de descarga VScreenS"
    _order = "create_date desc, id desc"
    _rec_name = "code"

    code = fields.Char(string="Código", required=True, index=True, copy=False, default=_new_code)
    aftvnews_code = fields.Char(
        string="Código Downloader (AFTVnews)",
        help="Código numérico de aftvnews.com compatible con la app Downloader en Android TV / Fire TV.",
    )
    product_tmpl_id = fields.Many2one(
        "product.template", string="Producto", required=True, ondelete="cascade"
    )
    product_name = fields.Char(string="Producto (nombre)", related="product_tmpl_id.name", store=True)
    company_id = fields.Many2one("vscreens.company", string="Empresa", ondelete="set null")
    partner_id = fields.Many2one("res.partner", string="Cliente", ondelete="set null")
    order_id = fields.Many2one("sale.order", string="Pedido", ondelete="set null")
    max_uses = fields.Integer(string="Máximo de usos", default=0, help="0 = ilimitado")
    uses = fields.Integer(string="Usos", default=0, readonly=True)
    expires_at = fields.Datetime(
        string="Válido hasta", default=lambda self: fields.Datetime.now() + timedelta(days=180)
    )
    active = fields.Boolean(string="Activo", default=True)
    valid_now = fields.Boolean(string="Vigente", compute="_compute_valid_now")
    notes = fields.Text(string="Notas")

    _code_uniq = models.Constraint("UNIQUE(code)", "Ese código de descarga ya existe.")

    @api.model
    def _shorten_aftvnews(self, target_url):
        """Intenta acortar target_url mediante go.aftvnews.com (Downloader by AFTVnews).
        Devuelve el código numérico (ej. '123456') o False si AFTVnews bloquea o falla."""
        if not target_url:
            return False
        try:
            import requests
            resp = requests.post(
                "https://go.aftvnews.com/",
                data={"url": target_url},
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Referer": "https://go.aftvnews.com/",
                },
                timeout=6,
            )
            if resp.status_code == 200:
                # Busca patrones como aftv.news/123456 o Short Code: 123456
                match = re.search(r"aftv\.news/(\d{4,10})", resp.text)
                if match:
                    return match.group(1)
        except Exception as exc:
            _logger.debug("No se pudo acortar en go.aftvnews.com: %s", exc)
        return False

    @api.model
    def generate(self, product, company=None, partner=None, order=None, max_uses=0, notes=None):
        """Genera un código único (reintenta en caso de colisión) y resuelve código AFTVnews."""
        for _ in range(10):
            try:
                with self.env.cr.savepoint():
                    rec = self.create({
                        "code": _new_code(),
                        "product_tmpl_id": product.id,
                        "company_id": company.id if company else False,
                        "partner_id": partner.id if partner else False,
                        "order_id": order.id if order else False,
                        "max_uses": max_uses,
                        "notes": notes,
                    })
                    aftv_code = (getattr(product, "aftvnews_code", "") or "").strip()
                    if not aftv_code:
                        aftv_code = self._shorten_aftvnews(rec.download_url()) or ""
                    if aftv_code:
                        rec.sudo().write({"aftvnews_code": aftv_code})
                    return rec
            except Exception:  # noqa: BLE001
                continue
        return self

    def _compute_valid_now(self):
        for record in self:
            record.valid_now = record.is_valid()

    def download_url(self):
        self.ensure_one()
        base = self.env["ir.config_parameter"].sudo().get_str(
            "vscreens.landing_public_url", "https://vscreens.inverpave.com"
        ).rstrip("/")
        return f"{base}/dl/{self.code}"

    def is_valid(self):
        self.ensure_one()
        return bool(
            self.active
            and (not self.expires_at or self.expires_at > fields.Datetime.now())
            and (not self.max_uses or self.uses < self.max_uses)
        )


class VscreensRequestLog(models.Model):
    """Registro ligero para limitar peticiones por IP y ruta."""

    _name = "vscreens.request.log"
    _description = "Registro de peticiones VScreenS"
    _order = "created_at desc"

    ip = fields.Char(string="IP", required=True, index=True)
    route = fields.Char(string="Ruta", required=True, index=True)
    created_at = fields.Datetime(string="Fecha", default=fields.Datetime.now, index=True)

    @api.model
    def is_limited(self, ip, route, limit=20, seconds=60):
        if not ip:
            return False
        since = fields.Datetime.now() - timedelta(seconds=seconds)
        count = self.sudo().search_count([
            ("ip", "=", ip),
            ("route", "=", route),
            ("created_at", ">=", since),
        ])
        self.sudo().create({"ip": ip[:64], "route": route[:64]})
        return count >= limit

    @api.model
    def cleanup_old(self, days=7):
        cutoff = fields.Datetime.now() - timedelta(days=days)
        self.sudo().search([("created_at", "<", cutoff)]).unlink()
        return True
