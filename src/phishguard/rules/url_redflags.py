# rule: url red flags

import re
from typing import List, Dict
from urllib.parse import urlparse
from phishguard.schema import EmailRecord, RuleHit, Severity
from phishguard.config import load_config


global cfg
cfg = load_config().get("rules").get("url_redflags")


## This function will be used in detect_urlredflags() below:
def analyze_url_features(url):
    """
    This function is use to analyze and identify the features of the URL that is passed into the function as parameter.
    The features include IP addresses, @ symbol, Number of subdomains, Shortened Domain, Suspicious Keyword in URL path, Suspicious TLDs.
    Returns features to detect_urlflags() after analyzing and identifying them.
    """
    sus_keyword: List[str] = cfg.get("suspicious_keyword_path")
    sus_tlds: List[str] = cfg.get("suspicious_tlds")
    tld_in_url =  (urlparse(url).netloc.split("."))[-1]
    url_path: str = urlparse(url.lower()).path
    
    # Features contains a dictionary with the key:value pair as shown:
    features = {
        "has_ip_address": bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", url or "")),
        "has_at_symbol": "@" in url,
        "num_subdomains": len(url.split(".")) - 2 if url else 0,
        "has_shortened_domain": urlparse(url).netloc.count('.') < 2,  # e.g., bit.ly,
        "suspicious_keyword_path": any(
            keyword in url_path for keyword in sus_keyword),
        "suspicious_tlds": any(
            keyword in tld_in_url for keyword in sus_tlds),
        
    }
    
    # Returns the dictionary of features to detect_urlredflags()
    return features



## Detects suspicious URL features
def detect_urlredflags(rec: EmailRecord):
    
    """
    Takes list of URL(s) in EmailRecord -> url_lists,  and detects for suspicious features in the URL(s). 
    Differing risk scores for each URL rule relative to impact on suspicions
    Accumulates number of hits for each rule from ALL URLs in the url_lists.
    """
    
    total_score = 0.0
    details: List[str] = []
    url_list: List[str] = rec.urls
    count_ip = 0
    count_at = 0
    count_subdomains = 0
    count_shortdomains = 0
    count_suskeyword = 0
    count_sustlds = 0
    
    
    if not cfg.get("enabled", True) or not url_list:
        return RuleHit("whitelist", True, 0.0, Severity.LOW, {"reason": "rule disabled"})
    
    else:
        for url in url_list:
            
            features: Dict = analyze_url_features(url) # calls on analyse url function to identify the features of URL
            
            ip_present: bool = features["has_ip_address"]
            at_present: bool = features["has_at_symbol"]
            num_subdomains: int = features["num_subdomains"]
            has_shortened_domain: bool = features["has_shortened_domain"]
            sus_keyword_path: bool = features["suspicious_keyword_path"]
            suspicious_tlds: bool = features["suspicious_tlds"]
            
            # Rules are set below, to determine if URL is suspicious
            # Rules hit and aggregates the total hits for each URL rule
            if ip_present:
                total_score += cfg.get("ip_url_penalty")  # 1.5 score
                count_ip += 1
                
            if at_present:
                total_score += cfg.get("at_symbol_penalty") # 1.5 score
                count_at += 1
                
            if num_subdomains > 3:
                total_score += cfg.get("subdomain_limit_penalty") # 2.0 score
                count_subdomains += num_subdomains
                
                
            if has_shortened_domain:
                total_score += cfg.get("shortener_penalty") # 1.2 score
                count_shortdomains += 1
                
            if sus_keyword_path:
                total_score += cfg.get("keyword_penalty") # 1.0 score
                count_suskeyword += 1
                
            if suspicious_tlds:
                total_score += cfg.get("suspicious_tld_penalty") # 1.0 score
                count_sustlds += 1
                
        details.append(f"ip_in_url: {count_ip}")        
        details.append(f"at_symbol: {count_at}")        
        details.append(f"no_of_subdomains: {count_subdomains}")        
        details.append(f"shortened_domain: {count_shortdomains}")        
        details.append(f"suspicious_keyword: {count_suskeyword}")        
        details.append(f"suspicious_tld: {count_sustlds}")        
        
        passed = (total_score < 4.0)  
        details = {"breakdown": " | ".join(details)} if details else {"hits": "none"}    
        severity = Severity.LOW if total_score < 4.0 else Severity.MEDIUM

        return RuleHit("url_redflags", passed, total_score, severity, details)
