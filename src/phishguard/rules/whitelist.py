# rule: whitelist

import re
from typing import List
from phishguard.schema import EmailRecord, RuleHit, Severity
from phishguard.config import load_config


def check_domain_whitelist(rec: EmailRecord):
    
    """
    Takes the rec.from_addr (sender's email address) and compares it with whitelisted domains in config.json.
    If include_subdomain: true, uses regex that includes subdomain in rec.from_addr for comparison with whitelist.
    Else, uses regex that ignores subdomain.
    """
    
    total_score = 0.0
    details: List[str] = []
    domain_whitelist = cfg.get("domains")
    emailaddr = rec.from_addr or ""
    
    if emailaddr != "":
        cfg = load_config().get("rules").get("whitelist")
        if not cfg.get("enabled", True):
            return RuleHit("whitelist", True, 0.0, Severity.LOW, {"reason": "rule disabled"})

        # Regex to search the email domain
        if not cfg.get("include_subdomains", True):
            sender_domain = re.search(r'@(?:[\w-]+\.)?([\w.-]+)', emailaddr).group(1) # regex to INCLUDE subdomain of sender addres 
        else:
            sender_domain = re.search(r'@([\w.-]+)', emailaddr).group(1) # regex to EXCLUDE subdomain of sender address
        

        if sender_domain is not None: # Handles the possibility where regex does not find domains in email

            # Compares domain in whitelist WITH domain of sender's email address
            if sender_domain in domain_whitelist:
                total_score = total_score + cfg.get("score_delta_on_match")
                details.append(f"domain: {sender_domain}")


    passed = (total_score < 0.0)  
    details = {"match found": " | ".join(details)} if details else {"match found": "none"}    
    severity = Severity.LOW if total_score < 0.0 else Severity.MEDIUM
    print(f"whitelist, {passed}, {total_score}, {severity}, {details}") 
    return RuleHit("whitelist", passed, total_score, severity, details)

