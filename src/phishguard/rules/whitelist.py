# rule: whitelist

import re
from typing import List , Dict
from phishguard.schema import EmailRecord, RuleHit, Severity
from phishguard.config import load_config


def check_domain_whitelist(rec: EmailRecord, config: Dict):
    
    """
    Takes the rec.from_addr (sender's email address) and compares it with whitelisted domains in config.json.
    If include_subdomain: true, uses regex that includes subdomain in rec.from_addr for comparison with whitelist.
    Else, uses regex that ignores subdomain.
    """
    cfg = cfg = (config or {}).get("rules", {}).get("whitelist", {})
    
    if not cfg.get("enabled", True):
        return RuleHit("whitelist", True, 0.0, Severity.LOW, {"reason": "rule disabled"})
    
    
    total_score = 0.0
    details: List[str] = []
    domain_whitelist: Dict[str: List] = cfg.get("domains")
    emailaddr:str = rec.from_addr or ""
    subdomain_enabled = cfg.get("include_subdomains")


    if emailaddr != "":
        # Extract everything after @ sign in email address
        if "@" in emailaddr:
            sender_domain: str = emailaddr.split("@")[1].lower()
        else:
            return RuleHit("whitelist", True, 0.0, Severity.LOW, {"reason": "invalid email format"})
        

        for whitelisted_domain in domain_whitelist.keys():
            if subdomain_enabled:
                
                # Handles case where include_subdomain enabled but there is no subdomain in sender's email
                if sender_domain == whitelisted_domain:
                    return RuleHit("whitelist", False, 0.0, Severity.LOW, {"reason":"email does not have subdomain" })
                 
                # Excludes SUBDOMAIN from email and checks if it is in DOMAIN whitelist first.
                if re.search(r'@(?:[\w-]+\.)?([\w.-]+)', emailaddr).group(1) == whitelisted_domain: 
                    
                    # Extract SUBDOMAIN from the sender's email
                    subdomain = re.search(r'@([\w.-]+)', emailaddr).group(1).replace(re.search(r'@(?:[\w-]+\.)?([\w.-]+)', emailaddr).group(1),"") # Removes Domain part from sender_domain, which results in ONLY the subdomain
                    subdomain = subdomain[:-1] 
                    
                    # Check if SUBDOMAIN is in the subdomain whitelist belonging to the domain.
                    if subdomain in domain_whitelist[whitelisted_domain]:
                        score_delta = cfg.get("score_delta_on_match", -0.5)
                        details.append(f"Domain {sender_domain} matches whitelist")
                        return RuleHit("whitelist", True, score_delta, Severity.LOW, {"matched_subdomain_and_domain": sender_domain})
                    else:
                        return RuleHit("whitelist", False, 0.0, Severity.LOW, {"reason": "subdomain is not whitelisted"})
                    
                     
            else:
                # Handles case where include_subdomain disabled but there IS subdomain in sender's email
                if sender_domain == whitelisted_domain or re.search(r'@(?:[\w-]+\.)?([\w.-]+)', emailaddr).group(1) == whitelisted_domain:
                    score_delta = cfg.get("score_delta_on_match", -0.5)
                    details.append(f"Domain {sender_domain} matches whitelist")
                    return RuleHit("whitelist", True, score_delta, Severity.LOW, {"matched_domain": whitelisted_domain})
        
        # Domain not in whitelist
        return RuleHit("whitelist", False, 0.0, Severity.LOW, {"reason": "domain not whitelisted"})
    
    # No email address provided
    return RuleHit("whitelist", False, 0.0, Severity.LOW, {"reason": "no email address"})