# rule: url red flags

import re
from urllib.parse import urlparse


## This function will be used in detect_suspicious_link_rules() below:
def analyze_url_features(url):
    parsed_url = urlparse(url)

    # Features contains a dictionary with the key:value pair as shown:
    features = {
        "length": len(url),
        "has_ip_address": bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_url.hostname or "")),
        "has_at_symbol": "@" in url,
        "num_subdomains": len(parsed_url.hostname.split(".")) - 2 if parsed_url.hostname else 0,
        "has_shortened_domain": parsed_url.netloc.count('.') < 1,  # e.g., bit.ly
        "has_uncommon_port": parsed_url.port is not None and parsed_url.port not in [80, 443],
        "has_suspicious_keywords": any(
            keyword in url.lower() for keyword in ["login", "verify", "update", "secure", "bank", "paypal"]),
    }

    # Returns the dictionary of features that will be used to detect any rule hits
    return features


## Detects suspicious URL features (Can be modified along the way)
def detect_suspicious_link_rules(url):
    features = analyze_url_features(url)
    
    # Rules are set below, to determine if URL is suspicious
    
    # Rules hit and return True, quoted words can be removed later
    if features["length"] > 100:
        return True, "URL is excessively long." 
    if features["has_ip_address"]:
        return True, "URL uses an IP address instead of a domain name."
    if features["has_at_symbol"]:
        return True, "URL contains an '@' symbol, often used in phishing."
    if features["num_subdomains"] > 3:
        return True, "URL has too many subdomains."
    if features["has_shortened_domain"]:
        return True, "URL uses a highly shortened domain, potentially disguising the true destination."
    if features["has_uncommon_port"]:
        return True, "URL uses an uncommon port number."
    if features["has_suspicious_keywords"]:
        return True, "URL contains suspicious keywords."

    # URL does not hit any of the rules above, return False
    return False, "URL appears legitimate based on rule-based analysis."
