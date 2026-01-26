import requests
from bs4 import BeautifulSoup
import re
import urllib3

# Disable warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_bcv_usd_rate():
    """
    Fetches the current USD exchange rate from the Central Bank of Venezuela (BCV).
    Returns the numeric value as a float or None if it fails.
    """
    url = "https://www.bcv.org.ve/"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        # verify=False is needed due to BCV certificate issues often encountered
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Look for the USD rate container
        # Usually inside id="dolar"
        dolar_container = soup.find('div', id='dolar')
        if not dolar_container:
            # Fallback: look for <strong> tags near "USD"
            usd_text = soup.find(string=re.compile("USD", re.IGNORECASE))
            if usd_text:
                dolar_container = usd_text.find_parent('div')
        
        if dolar_container:
            rate_text = dolar_container.find('strong').text.strip()
            # Convert "36,2045" or "36.2045" to float
            rate_val = float(rate_text.replace(',', '.'))
            return rate_val
            
    except Exception as e:
        print(f"Error fetching BCV rate: {e}")
    return None
