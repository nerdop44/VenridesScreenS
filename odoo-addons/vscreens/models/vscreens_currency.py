import logging
import re
from datetime import datetime

from odoo import api, fields, models

_logger = logging.getLogger(__name__)

ICP_RATE = "vscreens.bcv_rate"
ICP_UPDATED = "vscreens.bcv_rate_updated"


def _parse_rate(html):
    try:
        from bs4 import BeautifulSoup
    except Exception:
        return None
    soup = BeautifulSoup(html, "html.parser")
    container = soup.find("div", id="dolar")
    if not container:
        node = soup.find(string=re.compile("USD", re.IGNORECASE))
        container = node.find_parent("div") if node else None
    if not container:
        return None
    strong = container.find("strong")
    if not strong:
        return None
    text = strong.get_text(strip=True).replace(",", ".")
    try:
        return float(text)
    except ValueError:
        return None


def get_bcv_rate(env):
    icp = env["ir.config_parameter"].sudo()
    cached = icp.get_str(ICP_RATE, default="")
    updated = icp.get_str(ICP_UPDATED, default="")
    try:
        cached_rate = float(cached) if cached else 0.0
    except ValueError:
        cached_rate = 0.0

    if cached_rate and updated:
        try:
            if datetime.fromisoformat(updated).date() == datetime.now().date():
                return cached_rate
        except ValueError:
            pass

    try:
        import requests
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        response = requests.get(
            "https://www.bcv.org.ve/",
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                )
            },
            timeout=15,
            verify=False,
        )
        response.raise_for_status()
        rate = _parse_rate(response.text)
        if rate:
            icp.set_str(ICP_RATE, str(rate))
            icp.set_str(ICP_UPDATED, datetime.now().isoformat())
            return rate
    except Exception as exc:
        _logger.warning("No se pudo obtener la tasa BCV: %s", exc)

    return cached_rate or 0.0


class VScreenSCurrency(models.AbstractModel):
    _name = "vscreens.currency"
    _description = "Servicio de moneda BCV"

    @api.model
    def get_rate(self):
        return get_bcv_rate(self.env)

    @api.model
    def cron_refresh_bcv(self):
        rate = get_bcv_rate(self.env)
        _logger.info("Tasa BCV actualizada: %s", rate)
        return rate
