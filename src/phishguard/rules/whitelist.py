# rule: whitelist

import re
from typing import List , Dict
from phishguard.schema import EmailRecord, RuleHit, Severity
from phishguard.config import load_config


def check_domain_whitelist(rec: EmailRecord):
    
    """
    Takes the rec.from_addr (sender's email address) and compares it with whitelisted domains in config.json.
    If include_subdomain: true, uses regex that includes subdomain in rec.from_addr for comparison with whitelist.
    Else, uses regex that ignores subdomain.
    """
    cfg = load_config().get("rules").get("whitelist")
    
    if not cfg.get("enabled", True):
        return RuleHit("whitelist", True, 0.0, Severity.LOW, {"reason": "rule disabled"})
    
    
    total_score = 0.0
    details: List[str] = []
    domain_whitelist: Dict[str: List] = cfg.get("domains")
    emailaddr:str = rec.from_addr or ""
    subdomain_enabled = cfg.get("include_subdomains")

    
    if emailaddr != "":
        # Extract domain from email address
        if "@" in emailaddr:
            sender_domain = emailaddr.split("@")[1].lower()
        else:
            return RuleHit("whitelist", True, 0.0, Severity.LOW, {"reason": "invalid email format"})
        
        # Check if domain is in whitelist
        for whitelisted_domain in domain_whitelist.keys():
            if subdomain_enabled:
                # Check if sender domain ends with whitelisted domain
                if sender_domain == whitelisted_domain or sender_domain.endswith("." + whitelisted_domain):
                    score_delta = cfg.get("score_delta_on_match", -0.5)
                    details.append(f"Domain {sender_domain} matches whitelist")
                    return RuleHit("whitelist", True, score_delta, Severity.LOW, {"matched_domain": whitelisted_domain})
            else:
                # Exact domain match only
                if sender_domain == whitelisted_domain:
                    score_delta = cfg.get("score_delta_on_match", -0.5)
                    details.append(f"Domain {sender_domain} matches whitelist")
                    return RuleHit("whitelist", True, score_delta, Severity.LOW, {"matched_domain": whitelisted_domain})
        
        # Domain not in whitelist
        return RuleHit("whitelist", False, 0.0, Severity.LOW, {"reason": "domain not whitelisted"})
    
    # No email address provided
    return RuleHit("whitelist", True, 0.0, Severity.LOW, {"reason": "no email address"})