import re
from typing import List, Dict
import math



def check_random_generated(s: str) -> bool:
    """Detect if an email local-part looks randomly generated."""
    if not s:
        return False
    s = s.lower()

    if len(s) < 4:
        return False

    digit_ratio = sum(c.isdigit() for c in s) / len(s)
    special_ratio = sum(not c.isalnum() for c in s) / len(s)
    vowel_ratio = sum(c in "aeiou" for c in s) / len(s)
    consonant_ratio = sum(c in "bcdfghjklmnpqrstvwxyz" for c in s) / len(s)

    freq = {ch: s.count(ch) / len(s) for ch in set(s)}
    entropy = -sum(p * math.log2(p) for p in freq.values())

    no_vowels = vowel_ratio < 0.15
    many_consonants = consonant_ratio > 0.7
    consecutive_consonants = bool(re.search(r"[bcdfghjklmnpqrstvwxyz]{5,}", s))
    alternating_underscore = bool(re.search(r"(?:[a-z]_){2,}", s))
    repeating_chars = bool(re.search(r"([a-z0-9])\1{2,}", s))

    score = sum([
        digit_ratio > 0.3,
        special_ratio > 0.2,
        no_vowels,
        many_consonants,
        consecutive_consonants,
        alternating_underscore,
        repeating_chars,
        entropy > 3.5
    ])

    return score >= 3

#==========================================
#           Whitelist Rule Logic          =
#==========================================

def check_whitelist_and_localpart(emailaddr: str, config: Dict):
    """
    Check if an email address:
    - Matches whitelist (with optional subdomain check)
    - Has random-looking local-part
    - Contains suspicious keywords
    """
    details = {}
    score = 0.0
    passed = True

    cfg = (config or {}).get("rules", {}).get("whitelist", {})
    whitelist_enabled = cfg.get("enabled", True)
    subdomain_enabled = cfg.get("include_subdomains", False)
    domain_whitelist: Dict[str, List] = cfg.get("domains", {})
    suspicious_words = (config or {}).get("rules", {}).get("keywords", {}).get("suspicious_email_localpart", {})

    if not emailaddr or "@" not in emailaddr:
        return False, 0.0, {"domain_whitelist": "no email address provided"}

    sender_localpart, sender_domain = emailaddr.lower().split("@")
    domain_match = False
    if whitelist_enabled:
    # Domain whitelist check
        for whitelisted_domain in domain_whitelist.keys():
            base_domain_match = re.search(r'@(?:[\w-]+\.)?([\w.-]+)', emailaddr).group(1)
            if subdomain_enabled:
                if base_domain_match == whitelisted_domain:
                    subdomain = sender_domain.replace(whitelisted_domain, "").rstrip(".")
                    if subdomain in domain_whitelist[whitelisted_domain]:
                        domain_match = True
                        break
            elif sender_domain == whitelisted_domain or base_domain_match == whitelisted_domain:
                domain_match = True
                break

        if domain_match:
            score += cfg.get("score_delta_on_match", -0.5)
            details["domain_whitelist"] = f"{emailaddr} matched whitelist"
        else:
            passed = False
            details["domain_whitelist"] = f"{emailaddr} NOT whitelisted"
    else:
        passed = False
        details["domain_whitelist"] = "rule disabled"
    # Local-part checks
    local_flags = []
    domain_flags = []

    if check_random_generated(sender_localpart):
        passed = False
        score += 0.9
        local_flags.append("appears random")

    if any(word in sender_localpart for word in suspicious_words):
        passed = False
        score += 0.9
        local_flags.append("contains suspicious keywords")

    if any(word in sender_domain for word in suspicious_words):
        passed = False
        score += 0.9
        domain_flags.append("domain contains suspicious keywords")

    details["local_part"] = (
        f"Local part '{sender_localpart}' {' and '.join(local_flags)}"
        if local_flags else f"Local part '{sender_localpart}' seems normal"
    )
    details["sender_domain"] = (
        f"Domain '{sender_domain}' {' and '.join(domain_flags)}"
        if domain_flags else f"Domain '{sender_domain}' seems normal"
    )

    return passed, score, details