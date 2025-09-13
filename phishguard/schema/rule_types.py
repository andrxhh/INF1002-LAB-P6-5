from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict

class Severity(Enum):
    LOW = auto(); MEDIUM = auto(); HIGH = auto(); CRITICAL = auto()

@dataclass
class RuleHit:
    rule_name: str
    passed: bool
    score_delta: float
    severity: Severity
    details: Dict[str, str]
