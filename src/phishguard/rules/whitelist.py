import re
from typing import List, Dict
from phishguard.schema import EmailRecord, RuleHit, Severity
from phishguard.config import load_config

#==========================================
#           Whitelist Rule Logic          =
#==========================================

def rule_domain_whitelist(rec: EmailRecord, config: Dict):
    """
    Checks if the sender's email domain (and optionally subdomain) is whitelisted.
    - If include_subdomain: true, checks both domain and subdomain.
    - If include_subdomain: false, checks only the domain.
    Returns a RuleHit indicating if the sender is whitelisted.
    """
    # Load whitelist rule config, or use empty dict if not present
    cfg = (config or {}).get("rules", {}).get("whitelist", {})
    
    # If whitelist rule is disabled, return early
    if not cfg.get("enabled", True):
        return RuleHit("whitelist", True, 0.0, Severity.LOW, {"reason": "rule disabled"})
    
    total_score = 0.0
    details: List[str] = []
    # Get the domain whitelist mapping from config
    domain_whitelist: Dict[str: List] = cfg.get("domains")
    # Sender's email address
    emailaddr: str = rec.from_addr or ""
    # Whether to include subdomains in whitelist check
    subdomain_enabled = cfg.get("include_subdomains")

    if emailaddr != "":
        # Extract domain part after '@' in email address
        if "@" in emailaddr:
            sender_domain: str = emailaddr.split("@")[1].lower()
        else:
            # Invalid email format (missing '@')
            return RuleHit("whitelist", False, 0.0, Severity.LOW, {"reason": "invalid email format"})
        
        # Iterate through all whitelisted domains
        for whitelisted_domain in domain_whitelist.keys():
            if subdomain_enabled:
                # If sender's domain matches exactly, but no subdomain present
                if sender_domain == whitelisted_domain:
                    return RuleHit("whitelist", False, 0.0, Severity.LOW, {"reason": "email does not have subdomain"})
                
                # Check if sender's domain (excluding subdomain) matches whitelist
                if re.search(r'@(?:[\w-]+\.)?([\w.-]+)', emailaddr).group(1) == whitelisted_domain: 
                    # Extract subdomain from sender's email
                    subdomain = re.search(r'@([\w.-]+)', emailaddr).group(1).replace(
                        re.search(r'@(?:[\w-]+\.)?([\w.-]+)', emailaddr).group(1), ""
                    )
                    subdomain = subdomain[:-1]  # Remove trailing dot
                    
                    # Check if subdomain is in whitelist for this domain
                    if subdomain in domain_whitelist[whitelisted_domain]:
                        score_delta = cfg.get("score_delta_on_match", -0.5)
                        details.append(f"Domain {sender_domain} matches whitelist")
                        return RuleHit("whitelist", True, score_delta, Severity.LOW, {"matched_subdomain_and_domain": sender_domain})
                    else:
                        return RuleHit("whitelist", False, 0.0, Severity.LOW, {"reason": "subdomain is not whitelisted"})
            else:
                # If subdomains are not included, check for domain match (with or without subdomain)
                if sender_domain == whitelisted_domain or re.search(r'@(?:[\w-]+\.)?([\w.-]+)', emailaddr).group(1) == whitelisted_domain:
                    score_delta = cfg.get("score_delta_on_match", -0.5)
                    details.append(f"Domain {sender_domain} matches whitelist")
                    return RuleHit("whitelist", True, score_delta, Severity.LOW, {"matched_domain": whitelisted_domain})
        
        # No matching domain found in whitelist
        return RuleHit("whitelist", False, 0.0, Severity.LOW, {"reason": "domain not whitelisted"})
    
    # No email address provided in record
    return RuleHit("whitelist", False, 0.0, Severity.LOW, {"reason": "no email address"})