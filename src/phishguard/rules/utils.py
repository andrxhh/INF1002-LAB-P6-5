from __future__ import annotations

import re
import unicodedata
from typing import Dict, Iterable, Tuple


# Regex for IPv4 address validation
_IPV4_RE   = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def to_ascii_domain(domain: str) -> str:
    """
        Convert a domain to its ASCII representation using IDNA encoding.
    """
    if not domain: 
        return ""
    d = domain.strip().rstrip(".").lower()
    try:
        return domain.encode("idna").decode("utf-8")
    except Exception:
        pass
    return d

def parse_email_domain(addr: str) -> str:
    """
        Extract the domain from an email address. Return an empty string if invalid.
    """
    if not addr or "@" not in addr:
        return ""
    return to_ascii_domain(addr.split("@", 1)[1])

def parse_url_host(url: str) -> str:
    """
        Host parser for HTTP(S) URLs.
        Accepts 'http://', 'https://' and 'www.'.
        Strips userInfo and port when applicable.
    """
    if not url:
        return ""
    strip_url = url.strip().lower()

    if strip_url.startswith('//'):
        strip_url = 'http:' + strip_url
    if strip_url.startswith('www.'):
        host = strip_url.split("/", 1)[0]
        return to_ascii_domain(host)
    if strip_url.startswith('https://'):
        host = strip_url[8:].split("/", 1)[0]
    elif strip_url.startswith('http://'):
        host = strip_url[7:].split("/", 1)[0]
    
    # Strip userInfo
    if "@" in host:
        host = host.split("@", 1)[1]
    
    # Strip port
    if ":" in host:
        host = host.split(":", 1)[0]
    return to_ascii_domain(host)

def is_ipv4_host(host: str) -> bool:
    """
        Check if host is a IPv4 address.
    """
    if not host:
        return False
    return bool(_IPV4_RE.match(host))

def registrable_domain(domain: str, effective_tld: Iterable[str]) -> str:
    """
        Effective Top Level Domain, take last two labels by default; If domain end with 
        an exception of ('co.uk', 'com.sg' etc), take last three labels.
    """
    d = to_ascii_domain(domain)
    if not d or "." not in d:
        return ""
    parts = d.split(".")
    etld = {e.lower().lstrip(".") for e in (effective_tld or [])}
    if len(parts) >= 3 and ".".join(parts[-2:]) in etld or len(parts) >= 3 and ".".join(parts[-3:]) in etld:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def same_registrable(domain1: str, domain2: str, effective_tld: Iterable[str]) -> bool:
    """
        Check if two domains have the same registrable domain.
    """
    return registrable_domain(domain1, effective_tld) == registrable_domain(domain2, effective_tld)
