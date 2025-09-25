import os
import sys
from copy import deepcopy
from typing import Dict

_TESTS_DIR = os.path.dirname(__file__)
_PROJECT_ROOT = os.path.abspath(os.path.join(_TESTS_DIR, '..'))
_SRC_DIR = os.path.join(_PROJECT_ROOT, 'src')
if _SRC_DIR not in sys.path:
    sys.path.append(_SRC_DIR)


from phishguard.scoring.aggregate import run_rules, aggregate, evaluate_email
from phishguard.schema import EmailRecord, RuleHit, Severity


BASE_REC = EmailRecord(
    from_display="Support",
    from_addr="support@nus.edu.sg",
    reply_to_addr=None,
    subject="Hello",
    body_text="This is a benign message.",
    body_html=None,
    urls=[], url_display_pairs=[], attachments=[], headers={},
    spf_pass=None, dkim_pass=None, dmarc_pass=None
)


TEST_THRESHOLDS = {"safe_max": 20, "phishing_min": 40}

def get_test_config():
    """
    Returns the config dictionary that will be passed to evaluate_email().
    This config is used inside aggregate.py to determine the classification.
    """
    return {"thresholds": TEST_THRESHOLDS}


def rule_keyword(email: EmailRecord, config: Dict) -> RuleHit:
    """Checks if the subject contains 'URGENT'."""
    if "URGENT" in email.subject:
        return RuleHit(
            rule_name="keywords",
            passed=False,
            score_delta=20.0,
            severity=Severity.CRITICAL,
            details={"kw": "URGENT"}
        )
    return RuleHit(
        rule_name="keywords",
        passed=True,
        score_delta=0,
        severity=Severity.LOW,
        details={}
    )

def rule_phirequest(email: EmailRecord, config: Dict) -> RuleHit:
    """Checks if the email body requests sensitive info like SSN or credit card."""
    if "SSN" in email.body_text or "credit card" in email.body_text:
        return RuleHit(
            rule_name="phi_request",
            passed=False,
            score_delta=30.0,
            severity=Severity.HIGH,
            details={}
        )
    return RuleHit(
        rule_name="phi_request",
        passed=True,
        score_delta=0,
        severity=Severity.LOW,
        details={}
    )


def testing_safe():
    """Test a benign email. Should be labeled 'Safe'."""
    email = deepcopy(BASE_REC)
    email.subject = "Weekly Newsletter"
    email.body_text = "Nothing malicious here."

    rules = [rule_keyword, rule_phirequest]
    config = get_test_config()

    # --- This calls evaluate_email() from aggregate.py ---
    hits, total_score, label = evaluate_email(email, rules, config)

    print("SAFE TEST:")
    print("hits:", hits)                 
    print("total_score:", total_score)   
    print("label:", label)               

    assert total_score == 0
    assert label == "Safe"
    assert all(hit.passed for hit in hits)

def testing_suspicious():
    """Test an email that triggers one rule. Should be labeled 'Unknown'."""
    email = deepcopy(BASE_REC)
    email.subject = "Update your payment info"
    email.body_text = "Please provide your credit card to continue."

    rules = [rule_keyword, rule_phirequest]
    config = get_test_config()

    hits, total_score, label = evaluate_email(email, rules, config)

    print("\nSUSPICIOUS TEST:")
    print("hits:", hits)
    print("total_score:", total_score)
    print("label:", label)

    assert total_score == 30         
    assert label == "Unknown"         
    assert hits[0].passed is True
    assert hits[1].passed is False

def testing_phishing():
    """Test an email that triggers both rules. Should be labeled 'Phishing'."""
    email = deepcopy(BASE_REC)
    email.subject = "URGENT: Account closing!"
    email.body_text = "Verify your identity now. Provide your SSN."

    rules = [rule_keyword, rule_phirequest]
    config = get_test_config()

    hits, total_score, label = evaluate_email(email, rules, config)

    print("\nPHISHING TEST:")
    print("hits:", hits)
    print("total_score:", total_score)
    print("label:", label)

    assert total_score == 50          
    assert label == "Phishing"        
    assert hits[0].passed is False
    assert hits[1].passed is False


if __name__ == "__main__":
    try:
        testing_safe()
        testing_suspicious()
        testing_phishing()
        print("\nAll tests passed!")
    except AssertionError as e:
        print(f"\nTEST FAILED: {e}")
        sys.exit(1)
