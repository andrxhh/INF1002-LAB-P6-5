import unittest
from phishguard.schema import EmailRecord
from phishguard.rules.url_redflags import detect_urlredflags
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


class TestUrlDetection(unittest.TestCase):
    def test_ipaddr_in_url(self): # TestCase : IP in URL
        rec_legit = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://www.google.com"]})
        rec_phish = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://172.217.16.142/"]})
        hit_pos = detect_urlredflags(rec_phish, CFG)
        hit_neg = detect_urlredflags(rec_legit, CFG)
        
        #expected score 1.5 for hit, 0.0 for no hit
        self.assertEqual(hit_pos.score_delta, 1.5)
        self.assertEqual(hit_neg.score_delta, 0.0)

    def test_at_symbol(self): # TestCase : @ in netloc of URL
        rec_legit = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://www.facebook.com"]})
        rec_phish = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["http://www.google.com@malicious.com"]})
        hit_pos = detect_urlredflags(rec_phish, CFG)
        hit_neg = detect_urlredflags(rec_legit, CFG)
        
        #expected score 1.5 for hit, 0.0 for no hit
        self.assertEqual(hit_pos.score_delta, 1.5)
        self.assertEqual(hit_neg.score_delta, 0.0)


        
    def test_subdomain_limit(self): # TestCase : More than 3 subdomains
        rec_legit = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://mail.google.com"]})
        rec_phish = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["http://login.paypal.com.secure.verify.example.com"]})
        hit_pos = detect_urlredflags(rec_phish, CFG)
        hit_neg = detect_urlredflags(rec_legit, CFG)
        
        #expected score 2.0 for hit, 0.0 for no hit
        self.assertEqual(hit_pos.score_delta, 2.0)
        self.assertEqual(hit_neg.score_delta, 0.0)

        
    def test_shorten_domain(self): # TestCase : Shortened domain match found in config
        rec_legit = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://www.amazon.com/product/12345"]})
        rec_phish = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://bit.ly/3xYzAbC"]})
        hit_pos = detect_urlredflags(rec_phish, CFG)
        hit_neg = detect_urlredflags(rec_legit, CFG)
        
        #expected score 1.5 for hit, 0.0 for no hit
        self.assertEqual(hit_pos.score_delta, 1.5)
        self.assertEqual(hit_neg.score_delta, 0.0)


    
    def test_suspicious_path(self): # TestCase : Suspicious keywords in path
        rec_legit = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://www.wikipedia.org/wiki/Python"]})
        rec_phish = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://secure-paypal.com/login/verify"]})
        hit_pos = detect_urlredflags(rec_phish, CFG)
        hit_neg = detect_urlredflags(rec_legit, CFG)
        
        #expected score 1.0 for hit, 0.0 for no hit
        self.assertEqual(hit_pos.score_delta, 1.0)
        self.assertEqual(hit_neg.score_delta, 0.0)


        
    def test_suspicious_tld(self): # TestCase : Suspicious Top Level Domains (TLDs)
        rec_legit = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://www.microsoft.com"]})
        rec_phish = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["http://secure-login.xyz"]})
        hit_pos = detect_urlredflags(rec_phish, CFG)
        hit_neg = detect_urlredflags(rec_legit, CFG)
        
        #expected score 1.0 for hit, 0.0 for no hit
        self.assertEqual(hit_pos.score_delta, 1.0)
        self.assertEqual(hit_neg.score_delta, 0.0)
        


    
    def test_combined_phishing(self): # TestCase : Combination of rules hit, indicating suspicious URL
        rec_phish = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["http://192.168.0.1@bit.ly/login"]})
        hit_pos = detect_urlredflags(rec_phish, CFG)
        
        #expected score 1.5 for ip + 1.5 for @ + 1.5 for shorten domain + 1.0 for suspicious path keyword = 5.5
        self.assertEqual(hit_pos.score_delta, 5.5)



    def test_legitimate_complex(self): # TestCase : Legitimate URL, no hits
        rec_legit = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://shop.amazon.co.uk/product/12345"]})
        hit_neg = detect_urlredflags(rec_legit, CFG)
        
        #expected score 0.0 , url has no hit as legitimate
        self.assertEqual(hit_neg.score_delta, 0.0)



    def test_edge_cases(self): # TestCase : URLs with blurred line between legitimate and suspicious, but both are legitimate
        legit1 = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://example.com/path?user=name@example.com"]})
        legit2 = BASE_REC.__class__(**{**BASE_REC.__dict__, "urls": ["https://www.example.tech"]})
        hit1 = detect_urlredflags(legit1, CFG)
        hit2 = detect_urlredflags(legit2, CFG)
        
        #expected score 0.0 , legitimate URLs
        self.assertEqual(hit1.score_delta, 0.0)
        self.assertEqual(hit2.score_delta, 0.0)

    
    


if __name__ == "__main__":
    unittest.main()
