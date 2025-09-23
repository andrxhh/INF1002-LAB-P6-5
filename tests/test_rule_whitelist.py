import unittest

from typing import List , Dict
from phishguard.schema import EmailRecord
from phishguard.rules.whitelist import check_domain_whitelist
from phishguard.config import load_config
import copy

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

EXAMPLE_WHITELIST =  {"rules": {
    "whitelist": {
      "enabled": True,
      "domains": {
        "nus.edu.sg":["meds"],
        "sit.edu.sg":[],
        "microsoft.com":[],
        "google.com":[],
        "paypal.com":[],
        "singpass.gov.sg":[]
      },
      "include_subdomains": "",
      "score_delta_on_match": -0.5
    }
}
                      }



class TestWhitelist(unittest.TestCase):
    
    # def test_enabled_true(self): # TestCase: Whitelist Check "enabled:true"
    #     TEST_ENABLED_TRUE: Dict = copy.deepcopy(EXAMPLE_WHITELIST)
    #     TEST_ENABLED_TRUE['rules']['whitelist']['enabled']  = True
    #     hit = check_domain_whitelist(BASE_REC, TEST_ENABLED_TRUE)
        
    #     # expected -0.5, because Whitelist is enabled and BASE_REC.from_addr is in whitelist
        
    #     self.assertEqual(hit.score_delta, -0.5) 
        
        
    
    # def test_enabled_false(self): # TestCase: Whitelist Check "enabled:false"
    #     TEST_ENABLED_FALSE: Dict = copy.deepcopy(EXAMPLE_WHITELIST)
    #     TEST_ENABLED_FALSE['rules']['whitelist']['enabled']  = False
    #     hit = check_domain_whitelist(BASE_REC, TEST_ENABLED_FALSE)
        
    #     # expected 0.0, because Whitelist is disabled no checks were doner, although BASE_REC.from_addr is in whitelist
        
    #     self.assertEqual(hit.score_delta, 0.0)
    
    
    
    
    def test_subdomain_enabled(self):
        TEST_SUBDOMAIN_ENABLED: Dict = copy.deepcopy(EXAMPLE_WHITELIST)
        TEST_SUBDOMAIN_ENABLED['rules']['whitelist']['include_subdomains'] = True
        
        #BASE_REC.from_addr is nus.edu.sg (no subdomains)
        
        CS_SUBD_REC = copy.deepcopy(BASE_REC)
        CS_SUBD_REC.from_addr = "support@cs.nus.edu.sg" # subdomain cs
        print(CS_SUBD_REC)
        
        MEDS_SUBD_REC = copy.deepcopy(BASE_REC)
        MEDS_SUBD_REC.from_addr = "support@meds.nus.edu.sg" # subdomain meds
        
        # nosubdomain_hit = check_domain_whitelist(BASE_REC, TEST_SUBDOMAIN_ENABLED)
        cs_hit = check_domain_whitelist(CS_SUBD_REC, TEST_SUBDOMAIN_ENABLED)
        meds_hit = check_domain_whitelist(MEDS_SUBD_REC, TEST_SUBDOMAIN_ENABLED)
        
        print(cs_hit)
        
        
        
        # expected -0.5, BASE_REC.from_addr is in whitelist
        
        
 
 
    # def test_subdomain_enabled(self):
    #     pass
    # def subdomains(self):
    #     pass
    # def test_non_matches(self):
    #     pass
    # def test_non_matches_subd(self):
    #     pass
    
if __name__ == "__main__":
    unittest.main()
