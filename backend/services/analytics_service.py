"""
Analytics Service — VenridesScreenS
Lightweight self-hosted analytics (no Google Analytics dependency).
Tracks page visits, referrers, device types, and provides dashboard data.
"""
import os
import json
import logging
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional
from user_agents import parse as ua_parse

logger = logging.getLogger("VenrideScreenS.Analytics")

# In-memory storage (persisted to file optionally)
_visits = []
_daily_counts = defaultdict(int)
_page_counts = defaultdict(int)
_referrer_counts = defaultdict(int)
_device_counts = defaultdict(int)
_country_counts = defaultdict(int)
MAX_VISITS = 5000  # Keep last 5000 visits in memory

DATA_FILE = os.getenv("ANALYTICS_DATA_FILE", "/app/analytics_data.json")


def _hash_ip(ip: str) -> str:
    """Hash IP for privacy"""
    return hashlib.sha256(f"venrides-{ip}".encode()).hexdigest()[:12]


def _detect_device_type(user_agent_str: str) -> str:
    """Detect device type from user agent"""
    try:
        ua = ua_parse(user_agent_str)
        if ua.is_mobile:
            return "mobile"
        elif ua.is_tablet:
            return "tablet"
        elif ua.is_bot:
            return "bot"
        else:
            return "desktop"
    except Exception:
        ua_lower = user_agent_str.lower()
        if any(m in ua_lower for m in ["mobile", "android", "iphone"]):
            return "mobile"
        elif any(t in ua_lower for t in ["ipad", "tablet"]):
            return "tablet"
        elif any(b in ua_lower for b in ["bot", "crawl", "spider"]):
            return "bot"
        return "desktop"


def _extract_referrer_source(referrer: str) -> str:
    """Extract source from referrer URL"""
    if not referrer or referrer == "":
        return "directo"
    ref_lower = referrer.lower()
    if "google" in ref_lower:
        return "Google"
    elif "facebook" in ref_lower or "fb.com" in ref_lower:
        return "Facebook"
    elif "instagram" in ref_lower:
        return "Instagram"
    elif "twitter" in ref_lower or "x.com" in ref_lower:
        return "Twitter/X"
    elif "whatsapp" in ref_lower:
        return "WhatsApp"
    elif "tiktok" in ref_lower:
        return "TikTok"
    elif "linkedin" in ref_lower:
        return "LinkedIn"
    elif "youtube" in ref_lower:
        return "YouTube"
    elif "venrides" in ref_lower:
        return "interno"
    else:
        return referrer[:50]


class AnalyticsService:
    """Lightweight self-hosted analytics"""

    def __init__(self):
        self._load_data()

    def _load_data(self):
        """Load persisted data if available"""
        global _visits, _daily_counts, _page_counts, _referrer_counts, _device_counts
        try:
            if os.path.exists(DATA_FILE):
                with open(DATA_FILE, 'r') as f:
                    data = json.load(f)
                _visits = data.get("visits", [])[-MAX_VISITS:]
                _daily_counts = defaultdict(int, data.get("daily_counts", {}))
                _page_counts = defaultdict(int, data.get("page_counts", {}))
                _referrer_counts = defaultdict(int, data.get("referrer_counts", {}))
                _device_counts = defaultdict(int, data.get("device_counts", {}))
                logger.info(f"Analytics loaded: {len(_visits)} visits")
        except Exception as e:
            logger.warning(f"Could not load analytics data: {e}")

    def _save_data(self):
        """Persist data to file"""
        try:
            data = {
                "visits": _visits[-MAX_VISITS:],
                "daily_counts": dict(_daily_counts),
                "page_counts": dict(_page_counts),
                "referrer_counts": dict(_referrer_counts),
                "device_counts": dict(_device_counts),
            }
            os.makedirs(os.path.dirname(DATA_FILE) or ".", exist_ok=True)
            with open(DATA_FILE, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logger.warning(f"Could not save analytics: {e}")

    def track_visit(self, ip: str, page: str, referrer: str = "",
                    user_agent: str = "", country: str = ""):
        """Track a page visit"""
        # Skip bots
        device_type = _detect_device_type(user_agent)
        if device_type == "bot":
            return

        now = datetime.utcnow()
        hashed_ip = _hash_ip(ip)
        source = _extract_referrer_source(referrer)
        date_key = now.strftime("%Y-%m-%d")

        visit = {
            "ip_hash": hashed_ip,
            "page": page or "/",
            "referrer": source,
            "device": device_type,
            "timestamp": now.isoformat(),
            "country": country or "unknown",
        }

        _visits.append(visit)
        if len(_visits) > MAX_VISITS:
            _visits.pop(0)

        _daily_counts[date_key] += 1
        _page_counts[page or "/"] += 1
        _referrer_counts[source] += 1
        _device_counts[device_type] += 1

        # Save every 10 visits
        if len(_visits) % 10 == 0:
            self._save_data()

    def get_dashboard(self) -> dict:
        """Get analytics dashboard data for admin panel"""
        now = datetime.utcnow()
        today = now.strftime("%Y-%m-%d")
        yesterday = (now - timedelta(days=1)).strftime("%Y-%m-%d")

        # Last 30 days trend
        trend = {}
        for i in range(30):
            d = (now - timedelta(days=i)).strftime("%Y-%m-%d")
            trend[d] = _daily_counts.get(d, 0)

        # Unique visitors today (by IP hash)
        today_visits = [v for v in _visits if v["timestamp"].startswith(today)]
        unique_today = len(set(v["ip_hash"] for v in today_visits))

        # Recent visits (last 50)
        recent = _visits[-50:][::-1]

        return {
            "total_visits": sum(_daily_counts.values()),
            "visits_today": _daily_counts.get(today, 0),
            "visits_yesterday": _daily_counts.get(yesterday, 0),
            "unique_today": unique_today,
            "trend_30d": dict(sorted(trend.items())),
            "top_pages": dict(sorted(_page_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "referrers": dict(sorted(_referrer_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "devices": dict(_device_counts),
            "recent_visits": recent[:30],
        }

    def save(self):
        """Force save"""
        self._save_data()


# Singleton
analytics_service = AnalyticsService()
