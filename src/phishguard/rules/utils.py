from __future__ import annotations

import re
from typing import Iterable

#==========================================
#           Regex Pattern Helpers         =
#==========================================

# Regex for IPv4 address validation
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

#==========================================
#           Domain Utilities              =
#==========================================

def to_ascii_domain(domain: str) -> str:
    """
    Convert a domain to its ASCII representation using IDNA encoding.
    Handles internationalized domain names (IDN).
    """
    if not domain: 
        return ""
    d = domain.strip().rstrip(".").lower()
    try:
        return domain.encode("idna").decode("utf-8")
    except Exception:
        pass
    return d

#==========================================
#           Email Utilities               =
#==========================================

def parse_email_domain(addr: str) -> str:
    """
    Extract the domain from an email address.
    Returns an empty string if the address is invalid.
    """
    if not addr or "@" not in addr:
        return ""
    return to_ascii_domain(addr.split("@", 1)[1])

#==========================================
#           URL Utilities                 =
#==========================================

def parse_url_host(url: str) -> str:
    """
    Extract the host from an HTTP(S) URL.
    Accepts 'http://', 'https://', and 'www.' prefixes.
    Strips user info and port if present.
    Returns the ASCII domain.
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
    else:
        host = strip_url

    # Strip user info if present
    if "@" in host:
        host = host.split("@", 1)[1]

    # Strip port if present
    if ":" in host:
        host = host.split(":", 1)[0]
    return to_ascii_domain(host)

#==========================================
#           IP Address Utilities          =
#==========================================

def is_ipv4_host(host: str) -> bool:
    """
    Check if the given host is a valid IPv4 address.
    """
    if not host:
        return False
    return bool(_IPV4_RE.match(host))

#==========================================
#           Registrable Domain Helpers    =
#==========================================

def registrable_domain(domain: str, effective_tld: Iterable[str]) -> str:
    """
    Get the registrable domain (e.g., example.com, example.co.uk).
    Uses the effective TLD list to handle multi-label TLDs (like 'co.uk').
    Returns an empty string if the domain is invalid.
    """
    d = to_ascii_domain(domain)
    if not d or "." not in d:
        return ""
    parts = d.split(".")
    etld = {e.lower().lstrip(".") for e in (effective_tld or [])}
    # Check for multi-label TLDs (e.g., 'co.uk', 'com.sg')
    if len(parts) >= 3 and ".".join(parts[-2:]) in etld or len(parts) >= 3 and ".".join(parts[-3:]) in etld:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def same_registrable(domain1: str, domain2: str, effective_tld: Iterable[str]) -> bool:
    """
    Check if two domains share the same registrable domain.
    Useful for phishing detection and domain comparison.
    """
    return registrable_domain(domain1, effective_tld) == registrable_domain(domain2, effective_tld)

#==========================================
#           Lookalike Domain Helpers      =
#==========================================

def build_lookalike_variants(pairs: Iterable[str]) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Build two maps of lookalike domain variants from inputs like "1: I" and "rm: m",
    Returns:
        - A map of single-character substitutions (e.g., '1' -> 'I')
        - A map of multi-character substitutions (e.g., 'rm' -> 'm')
    """
    char_map, seq_map = {}, {}
    for pair in pairs:
        if ":" not in pair:
            continue
        left, right = pair.split(":", 1)
        left = left.strip()
        right = right.strip()
        if not left or not right:
            continue
        if len(left) == 1:
            char_map[left] = right
        else:
            seq_map[left] = right
    return char_map, seq_map