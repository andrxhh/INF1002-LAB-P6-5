# Import individual rule functions from their respective modules
from .whitelist_and_header import rule_domain_whitelist
from .url_redflags import rule_urlredflags
from .keywords import rule_keywords
from .lookalike_domain import rule_lookalike_domain
from .attachments import rule_risky_attachments

# List of all rule functions to be applied by the phishguard system
RULES = [
    rule_domain_whitelist,      # Checks if the domain is whitelisted (additional checks on headers)
    rule_urlredflags,           # Detects suspicious URL patterns
    rule_keywords,              # Searches for phishing-related keywords
    rule_lookalike_domain,      # Identifies lookalike domains
    rule_risky_attachments,     # Flags risky file attachments
]
