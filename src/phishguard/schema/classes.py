from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

@dataclass
class EmailRecord:
    from_display: str
    from_addr: str
    reply_to_addr: Optional[str]
    subject: str
    body_text: str
    body_html: Optional[str]
    urls: List[str]
    url_display_pairs: List[Tuple[str, str]]
    attachments: List[str]
    headers: Dict[str, str]
    spf_pass: Optional[bool]
    dkim_pass: Optional[bool]
    dmarc_pass: Optional[bool]

class Severity(Enum):
    LOW = auto(); MEDIUM = auto(); HIGH = auto(); CRITICAL = auto()

@dataclass
class RuleHit:
    rule_name: str
    passed: bool # True will mean that the rule did not match anything suspicious, False means it did
    score_delta: float # Score
    severity: Severity 
    details: Dict[str, str] #{"string": "string"}