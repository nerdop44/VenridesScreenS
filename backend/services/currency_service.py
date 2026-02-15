import logging
import asyncio
import re
import requests
import urllib3
import json
from bs4 import BeautifulSoup
from redis import Redis
import os

# Disable warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("VenrideScreenS.Currency")

class CurrencyService:
    def __init__(self):
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        try:
            self.redis = Redis.from_url(redis_url, decode_responses=True)
            logger.info(f"CurrencyService initialized with Redis at {redis_url}")
        except Exception as e:
            logger.warning(f"Could not connect to Redis: {e}. Caching disabled.")
            self.redis = None
            
        self.cache_key = "bcv_usd_rate"
        self.fallback_key = "bcv_usd_rate_fallback"
        self.cache_ttl = 3600  # 1 hour

    def get_rate(self) -> float:
        """
        Get the current USD rate. Priority: Cache -> BCV Scraping -> Fallback -> Default.
        """
        # 1. Try Cache
        if self.redis:
            try:
                cached = self.redis.get(self.cache_key)
                if cached:
                    return float(cached)
            except Exception as e:
                logger.error(f"Error reading from Redis cache: {e}")

        # 2. Try Scraping BCV
        rate = self._fetch_from_bcv()
        
        if rate:
            # Update cache and fallback
            if self.redis:
                try:
                    self.redis.setex(self.cache_key, self.cache_ttl, str(rate))
                    self.redis.set(self.fallback_key, str(rate))
                except Exception as e:
                    logger.error(f"Error saving to Redis: {e}")
            return rate

        # 3. Try Fallback from Redis (last successful fetch)
        if self.redis:
            try:
                fallback = self.redis.get(self.fallback_key)
                if fallback:
                    logger.warning("Using fallback BCV rate from Redis")
                    return float(fallback)
            except Exception:
                pass

        # 4. Critical Fallback (Hardcoded historical or safety value if all fails)
        logger.error("All BCV rate sources failed. Using hardcoded emergency rate.")
        return 45.0  # Safe approximate if everything goes down

    def _fetch_from_bcv(self) -> float:
        """Internal scraping logic from BCV"""
        url = "https://www.bcv.org.ve/"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        try:
            response = requests.get(url, headers=headers, timeout=15, verify=False)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Target the specific container for USD
            dolar_container = soup.find('div', id='dolar')
            if not dolar_container:
                # Fallback scraping logic
                usd_text = soup.find(string=re.compile("USD", re.IGNORECASE))
                if usd_text:
                    dolar_container = usd_text.find_parent('div')
            
            if dolar_container:
                rate_text = dolar_container.find('strong').text.strip()
                # Clean and convert "36,2045" -> 36.2045
                rate_val = float(rate_text.replace(',', '.'))
                return rate_val
                
        except Exception as e:
            logger.error(f"Scraping BCV failed: {e}")
        return None

# Singleton instance
currency_service = CurrencyService()
