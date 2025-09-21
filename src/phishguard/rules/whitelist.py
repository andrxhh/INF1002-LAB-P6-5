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
        # # Regex to search the email domain
        sender_domainonly = re.search(r'@(?:[\w-]+\.)?([\w.-]+)', emailaddr).group(1) # regex to EXCLUDE subdomain of sender addres 
  
        if sender_domainonly is not None: # Handles the possibility where regex does not find domains in email
            # Compares domain in whitelist WITH domain of sender's email address
            if sender_domainonly in domain_whitelist:
                if subdomain_enabled:
                    
                    sender_withsubdomain = re.search(r'@([\w.-]+)', emailaddr).group(1)
                    
                    subdomain_list : List[str] = domain_whitelist.get(sender_domainonly)    
                    extract_subdomain = sender_withsubdomain.replace("."+sender_domainonly, "")
                
                    if extract_subdomain in subdomain_list:
                        
                        total_score = total_score + cfg.get("score_delta_on_match")
                        details.append(f"domain: {sender_withsubdomain}")
                        
                else:
                    total_score = total_score + cfg.get("score_delta_on_match")
                    details.append(f"domain: {sender_domainonly}")
                    


    passed = (total_score < 0.0)  
    details = {"match found": " | ".join(details)} if details else {"match found": "none"}    
    severity = Severity.LOW if total_score < 0.0 else Severity.MEDIUM
     
    return RuleHit("whitelist", passed, total_score, severity, details)



# BASE_REC = EmailRecord(
#     from_display="Support",
#     from_addr="support@meds.nus.edu.sg",
#     reply_to_addr=None,
#     subject="Hello",
#     body_text="This is a benign message.",
#     body_html=None,
#     urls=[], url_display_pairs=[], attachments=[], headers={},
#     spf_pass=None, dkim_pass=None, dmarc_pass=None
# )

# print(check_domain_whitelist(BASE_REC))