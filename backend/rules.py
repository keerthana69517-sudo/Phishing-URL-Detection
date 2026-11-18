import re
from urllib.parse import urlparse

def _parse(url):
    try:
        return urlparse(url)
    except Exception:
        return None

def is_ip_host(url):
    u = _parse(url)
    if not u or not u.hostname:
        return False
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", u.hostname))

def has_suspicious_tld(url):
    u = _parse(url)
    if not u or not u.hostname:
        return False
    tld = u.hostname.split(".")[-1]
    return tld in {"zip", "mov", "top", "xyz", "gq", "cf", "tk", "ml", "icu", "cam"}

def has_many_subdomains(url):
    u = _parse(url)
    if not u or not u.hostname:
        return False
    return u.hostname.count(".") >= 3

def contains_at_symbol(url):
    return "@" in url

def contains_misleading_brand(url):
    return bool(re.search(r"(payp[ai]l|micr0soft|goog1e|faceb00k|appleid|secure\-?login)", url, re.I))

def uses_url_shortener(url):
    return bool(re.search(r"(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy)", url, re.I))

def has_suspicious_path_keywords(url):
    return bool(re.search(r"(verify|account|login|signin|update|confirm|reset|secure)", url, re.I))

def long_url(url):
    return len(url) >= 100

def hyphenated_domain(url):
    u = _parse(url)
    if not u or not u.hostname:
        return False
    return "-" in u.hostname

def has_hex_in_path(url):
    u = _parse(url)
    if not u:
        return False
    return bool(re.search(r"%[0-9a-fA-F]{2}", u.path))

RULES = [
    {"id": "ip_host", "name": "Uses raw IP address as host", "weight": 3, "check": is_ip_host},
    {"id": "shortener", "name": "URL shortener detected", "weight": 2, "check": uses_url_shortener},
    {"id": "suspicious_tld", "name": "Suspicious TLD used", "weight": 2, "check": has_suspicious_tld},
    {"id": "many_subdomains", "name": "Excessive subdomains", "weight": 2, "check": has_many_subdomains},
    {"id": "at_symbol", "name": "Contains '@' redirection trick", "weight": 2, "check": contains_at_symbol},
    {"id": "brand_spoof", "name": "Potential brand spoofing", "weight": 3, "check": contains_misleading_brand},
    {"id": "suspicious_path", "name": "Suspicious path keywords", "weight": 1, "check": has_suspicious_path_keywords},
    {"id": "long_url", "name": "Unusually long URL", "weight": 1, "check": long_url},
    {"id": "hyphenated_domain", "name": "Hyphenated domain name", "weight": 1, "check": hyphenated_domain},
    {"id": "hex_in_path", "name": "Encoded/obfuscated path", "weight": 1, "check": has_hex_in_path},
]