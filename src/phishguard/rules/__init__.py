# put rule imports here when ready
from .whitelist import check_domain_whitelist
from .url_redflags import detect_urlredflags
from .keywords import rule_keywords
from .lookalike_domain import rule_lookalike_domain
from .attachments import rule_risky_attachments

RULES = [
    check_domain_whitelist,
    detect_urlredflags,
    rule_keywords,
    rule_lookalike_domain,
    rule_risky_attachments,
]


