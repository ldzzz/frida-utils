import ipapi
from functools import lru_cache


"""
Dict Example for ip ret

    "ip": "8.8.8.8",
    "version": "IPv4",
    "city": "Mountain View",
    "region": "California",
    "region_code": "CA",
    "country": "US",
    "country_name": "United States",
    "country_code": "US",
    "country_code_iso3": "USA",
    "country_capital": "Washington",
    "country_tld": ".us",
    "continent_code": "NA",
    "in_eu": False,
    "postal": "Sign up to access",
    "latitude": "Sign up to access",
    "longitude": "Sign up to access",
    "timezone": "America/Los_Angeles",
    "utc_offset": "-0700",
    "country_calling_code": "+1",
    "currency": "USD",
    "currency_name": "Dollar",
    "languages": "en-US,es-US,haw,fr",
    "country_area": 9629091.0,
    "country_population": 327167434.0,
    "message": "Please message us at ipapi.co/trial for full access",
    "asn": "AS15169",
    "org": "GOOGLE"
"""


@lru_cache(maxsize=None)
def ip_info(ip: str) -> dict:
    """Returns information about ip

    Args:
        ip (str): ip address

    Returns:
        dict: information about given ip address
    """
    ip_data = ipapi.location(ip)
    return ip_data
