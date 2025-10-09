import re
from email.utils import parseaddr
from typing import Dict
from phishguard.schema import RuleHit, Severity, EmailRecord  


def rule_headers_analyse(rec: EmailRecord, config: Dict) -> RuleHit: 
    """
    Analyses Anomalies in Headers of emails:
    - FROM header and display name (if present) mismatches
    - REPLY-TO header does not have same domain as the sender's email address domain
    - TO header containing Undisclosed recipients, sign of mass spamming
    - RECEIVED header counts > 5 times, sign of proxying or anonymization
    Returns a RuleHit.
    """
    details = {}
    score = 0.0
    passed = True
    cfg = (config or {}).get("rules", {}).get("headers", {})
    
    # FROM header and display name mismatch 
    from_header = rec.headers.get("from", "")
    display_name, email_fromheader = parseaddr(from_header)
    if email_fromheader and display_name:
        local_part, *_ = email_fromheader.split("@")
        norm_display = re.sub(r'[^a-z0-9]', '', display_name.lower())
        norm_local = re.sub(r'[^a-z0-9]', '', local_part.lower())
        common_chars = sum(1 for c in norm_display if c in norm_local)
        ratio = common_chars / max(len(norm_display), 1)

        if ratio < 0.6:
            passed = False
            score += cfg.get("from_header_mismatch")
            details["from_header"] = f"Display name '{display_name}' differs from local part '{local_part}'"
        else:
            details["from_header"] = f"Display name '{display_name}' matches local part '{local_part}'"
    else:
        details["from_header"] = "From header empty or invalid"

    # REPLY-TO mismatch 
    reply_to = rec.headers.get("reply-to", "")
    if reply_to:
        from_domain = email_fromheader.split("@")[-1] if email_fromheader else ""
        reply_domain = reply_to.split("@")[-1]
        if reply_domain != from_domain:
            passed = False
            score += cfg.get("reply_to_mismatch")
            details["reply_to"] = f"Reply-To domain '{reply_domain}' differs from From domain '{from_domain}'"
        else:
            details["reply_to"] = "Reply-To matches From"
    else:
        details["reply_to"] = "No Reply-To header"

    # TO header containing Undisclosed recipients
    to_header = rec.headers.get("to", "")
    if "undisclosed" in to_header.lower():
        passed = False
        score += cfg.get("to_header_penalty")
        details["undisclosed_recipients"] = "To header contains undisclosed recipients"
    else:
        details["undisclosed_recipients"] = "Recipients visible"

    # RECEIVED header anomalies
    received_headers = rec.headers.get("received", "")
    num_hops = len(received_headers.split("\n"))
    if num_hops > cfg.get("max_hops", 5):
        passed = False
        score += cfg.get("max_hops_penalty")
        details["received_hops"] = f"Email has excessive hops ({num_hops})"
    else:
        details["received_hops"] = f"{num_hops} hops"


    severity = Severity.MEDIUM if score >= 2.0 else Severity.LOW

    return RuleHit("whitelist", passed, score, severity, details)