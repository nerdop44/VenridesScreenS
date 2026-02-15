import requests
import logging

logger = logging.getLogger("VenrideScreenS.URLShortener")

def shorten_url(url: str) -> str:
    """Shorten a URL using TinyURL API (no key required for basic use)"""
    try:
        # Use TinyURL free API
        api_url = f"http://tinyurl.com/api-create.php?url={url}"
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            return response.text
        logger.warning(f"TinyURL failed with status {response.status_code}")
    except Exception as e:
        logger.error(f"Error shortening URL: {e}")
    
    return url  # Fallback to original URL
