import re
from typing import List, Dict
from phishguard.schema import EmailRecord, RuleHit, Severity

from email.utils import parseaddr
import ipaddress
import math


#==========================================
#           Whitelist Rule Logic          =
#==========================================

# def rule_domain_whitelist(rec: EmailRecord, config: Dict):
#     """
#     Checks if the sender's email domain (and optionally subdomain) is whitelisted.
#     - If include_subdomain: true, checks both domain and subdomain.
#     - If include_subdomain: false, checks only the domain.
#     Returns a RuleHit indicating if the sender is whitelisted.
#     """
#     # Load whitelist rule config, or use empty dict if not present
#     cfg = (config or {}).get("rules", {}).get("whitelist", {})
    
#     # If whitelist rule is disabled, return early
#     if not cfg.get("enabled", True):
#         return RuleHit("whitelist", True, 0.0, Severity.LOW, {"reason": "rule disabled"})
    
#     total_score = 0.0
#     details: List[str] = []
#     # Get the domain whitelist mapping from config
#     domain_whitelist: Dict[str: List] = cfg.get("domains")
#     # Sender's email address
#     emailaddr: str = rec.from_addr or ""
#     # Whether to include subdomains in whitelist check
#     subdomain_enabled = cfg.get("include_subdomains")

#     if emailaddr != "":
#         # Extract domain part after '@' in email address
#         if "@" in emailaddr:
#             sender_domain: str = emailaddr.split("@")[1].lower()
#         else:
#             # Invalid email format (missing '@')
#             return RuleHit("whitelist", False, 0.0, Severity.LOW, {"reason": "invalid email format"})
        
#         # Iterate through all whitelisted domains
#         for whitelisted_domain in domain_whitelist.keys():
#             if subdomain_enabled:
#                 # If sender's domain matches exactly, but no subdomain present
#                 if sender_domain == whitelisted_domain:
#                     return RuleHit("whitelist", False, 0.0, Severity.LOW, {"reason": "email does not have subdomain"})
                
#                 # Check if sender's domain (excluding subdomain) matches whitelist
#                 if re.search(r'@(?:[\w-]+\.)?([\w.-]+)', emailaddr).group(1) == whitelisted_domain: 
#                     # Extract subdomain from sender's email
#                     subdomain = re.search(r'@([\w.-]+)', emailaddr).group(1).replace(
#                         re.search(r'@(?:[\w-]+\.)?([\w.-]+)', emailaddr).group(1), ""
#                     )
#                     subdomain = subdomain[:-1]  # Remove trailing dot
                    
#                     # Check if subdomain is in whitelist for this domain
#                     if subdomain in domain_whitelist[whitelisted_domain]:
#                         score_delta = cfg.get("score_delta_on_match", -0.5)
#                         details.append(f"Domain {sender_domain} matches whitelist")
#                         return RuleHit("whitelist", True, score_delta, Severity.LOW, {"matched_subdomain_and_domain": sender_domain})
#                     else:
#                         return RuleHit("whitelist", False, 0.0, Severity.LOW, {"reason": "subdomain is not whitelisted"})
#             else:
#                 # If subdomains are not included, check for domain match (with or without subdomain)
#                 if sender_domain == whitelisted_domain or re.search(r'@(?:[\w-]+\.)?([\w.-]+)', emailaddr).group(1) == whitelisted_domain:
#                     score_delta = cfg.get("score_delta_on_match", -0.5)
#                     details.append(f"Domain {sender_domain} matches whitelist")
#                     return RuleHit("whitelist", True, score_delta, Severity.LOW, {"matched_domain": whitelisted_domain})
        
#         # No matching domain found in whitelist
#         return RuleHit("whitelist", False, 0.0, Severity.LOW, {"reason": "domain not whitelisted"})
    
#     # No email address provided in record
#     return RuleHit("whitelist", False, 0.0, Severity.LOW, {"reason": "no email address"})


def check_random_generated(s: str) -> bool:
    """Detect if an email local-part looks randomly generated."""
    if not s:
        return False
    s = s.lower()

    # Ignore short or very common ones
    if len(s) < 4:
        return False

    # Metrics
    digit_ratio = sum(c.isdigit() for c in s) / len(s)
    special_ratio = sum(not c.isalnum() for c in s) / len(s)
    vowel_ratio = sum(c in "aeiou" for c in s) / len(s)
    consonant_ratio = sum(c in "bcdfghjklmnpqrstvwxyz" for c in s) / len(s)

    # Entropy calculation (randomness)
    freq = {ch: s.count(ch) / len(s) for ch in set(s)}
    entropy = -sum(p * math.log2(p) for p in freq.values())

    # Patterns
    no_vowels = vowel_ratio < 0.15
    many_consonants = consonant_ratio > 0.7
    consecutive_consonants = bool(re.search(r"[bcdfghjklmnpqrstvwxyz]{5,}", s))
    alternating_underscore = bool(re.search(r"(?:[a-z]\_){2,}", s))
    repeating_chars = bool(re.search(r"([a-z0-9])\1{2,}", s))

    # Heuristic scoring
    score = 0
    if digit_ratio > 0.3:
        score += 1
    if special_ratio > 0.2:
        score += 1
    if no_vowels:
        score += 1
    if many_consonants:
        score += 1
    if consecutive_consonants:
        score += 1
    if alternating_underscore:
        score += 1
    if repeating_chars:
        score += 1
    if entropy > 3.5:  # high entropy = random-looking
        score += 1

    # Threshold can be tuned (>=3-4 is likely random)
    return score >= 3



def rule_domain_whitelist(rec: EmailRecord, config: Dict):
    """
    Combined rule:
    - Domain whitelist (with optional subdomain check)
    - Undisclosed recipients check
    - Header phishing indicators:
        * Reply-To mismatch
        * Random-looking local part
        * Suspicious Received headers (private IPs, excessive hops)
    Returns a single RuleHit with aggregated score and details.
    """
    cfg = (config or {}).get("rules", {}).get("whitelist", {})
    score = 0.0
    details: Dict[str, str] = {}
    passed = True  # True only if all sub-rules pass

    # --- 1. Domain whitelist check ---
    emailaddr = rec.from_addr or ""
    subdomain_enabled = cfg.get("include_subdomains", False)
    domain_whitelist: Dict[str, List] = cfg.get("domains", {})

    if emailaddr != "" and "@" in emailaddr:
        sender_domain = emailaddr.split("@")[1].lower()
        sender_localpart = emailaddr.split("@")[0].lower()
        
        domain_match = False
        for whitelisted_domain in domain_whitelist.keys():
            if subdomain_enabled:
                base_domain_match = re.search(r'@(?:[\w-]+\.)?([\w.-]+)', emailaddr).group(1)
                if base_domain_match == whitelisted_domain:
                    subdomain = sender_domain.replace(whitelisted_domain, "").rstrip(".")
                    if subdomain in domain_whitelist[whitelisted_domain]:
                        domain_match = True
                        break
            else:
                base_domain_match = re.search(r'@(?:[\w-]+\.)?([\w.-]+)', emailaddr).group(1)
                if sender_domain == whitelisted_domain or base_domain_match == whitelisted_domain:
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
        details["domain_whitelist"] = "no email address provided"


    # Suspicious keywords list
    suspicious_words = [
    # Adult / Sexual Content
    "sex", "xxx", "porn", "nude", "adult", "erotic", "horny", "dating", "hookup", "milf", "teen",
    
    # Financial / Scam Terms
    "loan", "credit", "cash", "money", "creditcard", "paypal", "bitcoin", "free", "prize", "reward", "bonus", "jackpot", "millionaire",
    
    # Generic Spam / Clickbait Terms
    "offer", "deal", "discount", "cheap", "win", "giveaway", "promo", "click", "urgent", "important", "alert", "limited",
    
    # Gambling / Gaming Terms
    "casino", "poker", "betting", "roulette", "blackjack", "lottery","smoking",
    
    # Suspicious or Random Patterns
    "aaa", "xxx", "girl_with_toys", "hot_babe", "sexy_queen",
    
    # Common Phishing / Impersonation Words
    "admin", "support", "service", "helpdesk", "security", "verification", "update", "account", "login", "bank"
]

    local_part_flags = []
    domain_flags = []
    # Check local part
    if check_random_generated(sender_localpart):
        passed = False
        score += 0.9
        local_part_flags.append("appears random")

    if any(word in sender_localpart for word in suspicious_words):
        passed = False
        score += 0.9
        local_part_flags.append("contains suspicious keywords")

    # Check domain part against suspicious list
    if any(word in sender_domain for word in suspicious_words):
        passed = False
        score += 0.9
        domain_flags.append("domain contains suspicious keywords")

    # Prepare details string
    if local_part_flags:
        details["local_part"] = f"Local part '{sender_localpart}' " + " and ".join(local_part_flags)
    else:
        details["local_part"] = f"Local part '{sender_localpart}' seems normal"

    if domain_flags:
        details["sender_domain"] = f"Domain '{sender_domain}' " + " and ".join(domain_flags)
    else:
        details["sender_domain"] = f"Domain '{sender_domain}' seems normal"
        
        
    # --- 2. From header / display name mismatch ---
    from_header = rec.headers.get("from", "")
    display_name, email_fromheader = parseaddr(from_header)

    if email_fromheader and display_name:
        local_part, *_ = email_fromheader.split("@")

        # Normalize both names
        norm_display = re.sub(r'[^a-z0-9]', '', display_name.lower())
        norm_local = re.sub(r'[^a-z0-9]', '', local_part.lower())

        # Compute similarity (simple ratio)
        common_chars = sum(1 for c in norm_display if c in norm_local)
        ratio = common_chars / max(len(norm_display), 1)

        if ratio < 0.6:  # threshold — 60% overlap is OK
            passed = False
            score += 0.5
            details["from_header"] = (
                f"Display name '{display_name}' differs significantly from local part '{local_part}'"
            )
        else:
            details["from_header"] = f"Display name '{display_name}' matches local part '{local_part}'"
    else:
        details["from_header"] = "From header empty or invalid"

    # --- 3. Reply-To mismatch ---
    reply_to = rec.headers.get("reply-to", "")
    if reply_to:
        
        from_domain = email_fromheader.split("@")[-1]
        reply_domain = reply_to.split("@")[-1]
        if reply_domain != from_domain:
            passed = False
            score += 0.5
            details["reply_to"] = f"Reply-To domain '{reply_domain}' differs from From domain '{from_domain}'"
        else:
            details["reply_to"] = "Reply-To matches From"
    else:
        details["reply_to"] = "No Reply-To header"

    # --- 4. Undisclosed recipients check ---
    to_header = rec.headers.get("to", "")
    if "undisclosed" in to_header.lower():
        passed = False
        score += 0.5
        details["undisclosed_recipients"] = "To header contains undisclosed recipients"
    else:
        details["undisclosed_recipients"] = "Recipients visible"

    # --- 5. Received header / path anomalies ---
    received_headers = rec.headers.get("received", "")
    received_lines = received_headers.split("\n")
    num_hops = len(received_lines)
    if num_hops > cfg.get("max_hops", 5):
        passed = False
        score += 0.3
        details["received_hops"] = f"Email has excessive hops ({num_hops})"
    else:
        details["received_hops"] = f"{num_hops} hops"


    # --- Determine overall severity ---
    severity = Severity.MEDIUM if score >= 2.0 else Severity.LOW

    return RuleHit("whitelist", passed, score, severity, details)