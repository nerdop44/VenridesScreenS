from services.currency_service import currency_service

def get_bcv_usd_rate():
    """
    Backward compatibility wrapper for the new CurrencyService.
    """
    return currency_service.get_rate()
