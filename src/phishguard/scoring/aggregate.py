# F: implement as provided earlier

from typing import  List
from ..schema import  RuleHit

def calculate_score(rule_hits: List[RuleHit])-> float:
    #To sum up the score from each rule stated
    return sum(hit.score_delta for hit in rule_hits)

def classify_email(score: float, thresholds:dict)-> str:
    """
    Thresholds:

    thresholds = {
    
    "safe" : 0,
    "suspicious": 5 ,
    "phishing" : 15
    
    }
    """

    if score < thresholds["suspicious"]:
        return "Safe"
    elif score < thresholds["phishing"]:
        return "Suspicious"
    else:
        return "Phishing"


def aggregate(rule_hits: List[RuleHit], thresholds: dict):
    score = calculate_score(rule_hits)
    label = classify_email(score , thresholds)

    return{
        "score" : score,
        "label" : label,
        "hits"  : [hit.dict for hit in rule_hits if hit is not None]
    }