import unittest
from phishguard.schema import EmailRecord
from phishguard.rules.whitelist import check_domain_whitelist
from phishguard.config import load_config
BASE_REC = EmailRecord(
    from_display="Support",
    from_addr="support@example.com",
    reply_to_addr=None,
    subject="Hello",
    body_text="This is a benign message.",
    body_html=None,
    urls=[], url_display_pairs=[], attachments=[], headers={},
    spf_pass=None, dkim_pass=None, dmarc_pass=None
)


CFG = load_config()

class TestWhitelist(unittest.TestCase):
    def test_exact_matches(self):
        pass
    def test_subdomains(self):
        pass
    def test_non_matches(self):
        pass
    def test_non_matches_subd(self):
        pass