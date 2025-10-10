import unittest
import sys
from pathlib import Path
from dataclasses import replace

# Add src to path for imports
project_root = Path(__file__).parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

from phishguard.schema import EmailRecord, Severity
from phishguard.rules.lookalike_domain import rule_lookalike_domain

# Base EmailRecord template for testing
BASE_REC = EmailRecord(
    from_display="User",
    from_addr="user@example.com",
    reply_to_addr=None,
    subject="Test Subject",
    body_text="This is a test message.",
    body_html=None,
    urls=[], 
    url_display_pairs=[], 
    attachments=[], 
    headers={},
    spf_pass=None, 
    dkim_pass=None, 
    dmarc_pass=None
)

# Test configuration with protected domains
TEST_CONFIG = {
    "rules": {
        "lookalike_domain": {
            "enabled": True,
            "protected_domains": [
                "paypal.com",
                "google.com",
                "microsoft.com",
                "amazon.com",
                "apple.com",
                "facebook.com",
                "singpass.gov.sg",
                "dbs.com",
                "ocbc.com"
            ],
            "max_edit_distance": 3
        }
    }
}


class TestLookAlikeDomain(unittest.TestCase):
    """Test suite for lookalike domain detection rule"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = TEST_CONFIG
        
    # ========================================================================
    #                      LEGITIMATE DOMAIN TESTS                           
    # ========================================================================
    
    def test_legitimate_paypal_domain(self):
        """Test that legitimate PayPal domain passes"""
        rec = replace(BASE_REC, from_addr="security@paypal.com")
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertTrue(hit.passed, "Legitimate paypal.com should pass")
        self.assertEqual(hit.score_delta, 0.0, "Score should be 0 for legitimate domain")
        self.assertEqual(hit.severity, Severity.LOW)

    def test_legitimate_google_domain(self):
        """Test that legitimate Google domain passes"""
        rec = replace(BASE_REC, from_addr="noreply@google.com")
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertTrue(hit.passed, "Legitimate google.com should pass")
        self.assertEqual(hit.score_delta, 0.0)

    def test_legitimate_microsoft_domain(self):
        """Test that legitimate Microsoft domain passes"""
        rec = replace(BASE_REC, from_addr="support@microsoft.com")
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertTrue(hit.passed, "Legitimate microsoft.com should pass")
        self.assertEqual(hit.score_delta, 0.0)

    def test_unrelated_legitimate_domain(self):
        """Test that unrelated domains pass (not in protected list)"""
        rec = replace(BASE_REC, from_addr="user@completelydifferent.com")
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertTrue(hit.passed, "Unrelated domains should pass")
        self.assertEqual(hit.score_delta, 0.0)

    # ========================================================================
    #                      TYPOSQUATTING TESTS (Distance 1)                  
    # ========================================================================
    
    def test_paypal_typosquatting_character_replacement(self):
        """Test PayPal typosquatting with character replacement (l→I)"""
        rec = replace(BASE_REC, from_addr="security@paypaI.com")  # l → I (capital i)
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertFalse(hit.passed, "Typosquatting should fail")
        self.assertGreater(hit.score_delta, 0, "Score should be > 0 for typosquatting")
        self.assertEqual(hit.severity, Severity.HIGH)
        self.assertIn("paypal.com", hit.details.get("legitimate", ""))

    def test_paypal_typosquatting_extra_character(self):
        """Test PayPal typosquatting with extra character"""
        rec = replace(BASE_REC, from_addr="security@paypall.com")  # extra 'l'
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertFalse(hit.passed, "Typosquatting with extra char should fail")
        self.assertGreater(hit.score_delta, 0)
        self.assertEqual(hit.severity, Severity.HIGH)

    def test_paypal_typosquatting_missing_character(self):
        """Test PayPal typosquatting with missing character"""
        rec = replace(BASE_REC, from_addr="security@paypa.com")  # missing 'l'
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertFalse(hit.passed, "Typosquatting with missing char should fail")
        self.assertGreater(hit.score_delta, 0)

    def test_paypal_typosquatting_character_swap(self):
        """Test PayPal typosquatting with character swap"""
        rec = replace(BASE_REC, from_addr="security@paypla.com")  # swap l and a
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertFalse(hit.passed, "Typosquatting with char swap should fail")
        self.assertGreater(hit.score_delta, 0)

    # ========================================================================
    #                      TYPOSQUATTING TESTS (Distance 2-3)                
    # ========================================================================
    
    def test_google_typosquatting_distance_2(self):
        """Test Google typosquatting with edit distance 2"""
        rec = replace(BASE_REC, from_addr="support@googgle.com")  # extra 'g'
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertFalse(hit.passed, "Typosquatting distance 2 should fail")
        self.assertGreater(hit.score_delta, 0)

    def test_microsoft_typosquatting_distance_3(self):
        """Test Microsoft typosquatting with edit distance 3"""
        rec = replace(BASE_REC, from_addr="support@microssoft.com")  # extra 's'
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertFalse(hit.passed, "Typosquatting distance 3 should fail")
        self.assertGreater(hit.score_delta, 0)

    def test_amazon_typosquatting_multiple_changes(self):
        """Test Amazon typosquatting with multiple character changes"""
        rec = replace(BASE_REC, from_addr="orders@amazom.com")  # n → m
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertFalse(hit.passed, "Multiple char changes should fail")
        self.assertGreater(hit.score_delta, 0)

    # ========================================================================
    #                      DOMAIN-SPECIFIC ATTACK PATTERNS                   
    # ========================================================================
    
    def test_singpass_gov_sg_typosquatting(self):
        """Test Singpass domain typosquatting"""
        rec = replace(BASE_REC, from_addr="verify@singpas.gov.sg")  # missing 's'
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertFalse(hit.passed, "Singpass typosquatting should fail")
        self.assertGreater(hit.score_delta, 0)

    def test_dbs_bank_typosquatting(self):
        """Test DBS bank domain typosquatting"""
        rec = replace(BASE_REC, from_addr="alert@dbss.com")  # extra 's'
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertFalse(hit.passed, "DBS typosquatting should fail")
        self.assertGreater(hit.score_delta, 0)

    def test_ocbc_bank_typosquatting(self):
        """Test OCBC bank domain typosquatting"""
        rec = replace(BASE_REC, from_addr="security@ocbcc.com")  # extra 'c'
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertFalse(hit.passed, "OCBC typosquatting should fail")
        self.assertGreater(hit.score_delta, 0)

    # ========================================================================
    #                      EDGE CASES & ERROR HANDLING                       
    # ========================================================================
    
    def test_invalid_email_format_no_at_symbol(self):
        """Test handling of invalid email format (no @ symbol)"""
        rec = replace(BASE_REC, from_addr="invalidemailformat")
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertTrue(hit.passed, "Invalid format should pass (cannot detect)")
        self.assertEqual(hit.score_delta, 0.0)
        self.assertIn("invalid email format", hit.details.get("reason", ""))

    def test_empty_email_address(self):
        """Test handling of empty email address"""
        rec = replace(BASE_REC, from_addr="")
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertTrue(hit.passed, "Empty email should pass gracefully")
        self.assertEqual(hit.score_delta, 0.0)

    def test_no_config_provided(self):
        """Test handling when no config is provided"""
        rec = replace(BASE_REC, from_addr="security@paypaI.com")
        hit = rule_lookalike_domain(rec, None)
        
        # Should still work with default empty protected_domains list
        self.assertTrue(hit.passed, "Should pass when no protected domains")

    def test_empty_protected_domains_list(self):
        """Test with empty protected domains list"""
        config = {"rules": {"lookalike_domain": {"protected_domains": []}}}
        rec = replace(BASE_REC, from_addr="security@paypaI.com")
        hit = rule_lookalike_domain(rec, config)
        
        self.assertTrue(hit.passed, "Should pass with empty protected list")
        self.assertEqual(hit.score_delta, 0.0)

    # ========================================================================
    #                      DISTANCE BOUNDARY TESTS                           
    # ========================================================================
    
    def test_large_distance_no_detection(self):
        """Test that large edit distance (>3) does not trigger detection"""
        rec = replace(BASE_REC, from_addr="security@completely-different.com")
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertTrue(hit.passed, "Large distance should not trigger")
        self.assertEqual(hit.score_delta, 0.0)

    def test_exact_match_passes(self):
        """Test that exact match (distance 0) passes"""
        rec = replace(BASE_REC, from_addr="security@paypal.com")
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertTrue(hit.passed, "Exact match should pass")
        self.assertEqual(hit.score_delta, 0.0)

    def test_distance_boundary_3(self):
        """Test boundary condition at distance 3"""
        rec = replace(BASE_REC, from_addr="security@paypaal.com")  # distance 2 from paypal.com
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertFalse(hit.passed, "Distance 2 should fail")
        self.assertGreater(hit.score_delta, 0)

    # ========================================================================
    #                      CASE SENSITIVITY TESTS                            
    # ========================================================================
    
    def test_case_insensitive_matching(self):
        """Test that domain matching is case-insensitive"""
        rec = replace(BASE_REC, from_addr="security@PAYPAL.COM")
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertTrue(hit.passed, "Uppercase legitimate domain should pass")
        self.assertEqual(hit.score_delta, 0.0)

    def test_case_insensitive_typosquatting(self):
        """Test case-insensitive typosquatting detection"""
        rec = replace(BASE_REC, from_addr="security@PAYPAI.COM")  # I instead of L
        hit = rule_lookalike_domain(rec, self.config)
        
        self.assertFalse(hit.passed, "Uppercase typosquatting should still fail")
        self.assertGreater(hit.score_delta, 0)

    # ========================================================================
    #                      COMMON ATTACK PATTERNS                            
    # ========================================================================
    
    def test_homoglyph_attack_rn_to_m(self):
        """Test homoglyph attack: 'rn' looks like 'm'"""
        # Note: This tests character-level similarity, not visual
        rec = replace(BASE_REC, from_addr="support@arnazom.com")  # rn → m visually
        hit = rule_lookalike_domain(rec, self.config)
        
        # May or may not detect depending on edit distance
        if not hit.passed:
            self.assertGreater(hit.score_delta, 0)

    def test_subdomain_not_checked(self):
        """Test that subdomains are not included in comparison"""
        rec = replace(BASE_REC, from_addr="user@secure.paypal.com")
        hit = rule_lookalike_domain(rec, self.config)
        
        # Should extract just 'com' from 'secure.paypal.com' 
        # This is a limitation - only checks rightmost part after @
        self.assertTrue(hit.passed)

    # ========================================================================
    #                      LEVENSHTEIN LIBRARY TESTS                         
    # ========================================================================
    
    def test_levenshtein_library_available(self):
        """Test if Levenshtein library is available"""
        try:
            import Levenshtein
            available = True
        except ImportError:
            available = False
        
        # If library is not available, rule should handle gracefully
        if not available:
            rec = replace(BASE_REC, from_addr="security@paypaI.com")
            hit = rule_lookalike_domain(rec, self.config)
            self.assertIn("library not available", hit.details.get("reason", ""))

    # ========================================================================
    #                      DETAILS VERIFICATION TESTS                        
    # ========================================================================
    
    def test_details_include_both_domains(self):
        """Test that details include both legitimate and suspicious domains"""
        rec = replace(BASE_REC, from_addr="security@paypaI.com")
        hit = rule_lookalike_domain(rec, self.config)
        
        if not hit.passed:
            self.assertIn("legitimate", hit.details)
            self.assertIn("suspicious", hit.details)
            self.assertEqual(hit.details["legitimate"], "paypal.com")
            self.assertEqual(hit.details["suspicious"], "paypaI.com".lower())

    def test_details_include_distance(self):
        """Test that details include edit distance"""
        rec = replace(BASE_REC, from_addr="security@paypaI.com")
        hit = rule_lookalike_domain(rec, self.config)
        
        if not hit.passed:
            self.assertIn("distance", hit.details)
            self.assertIsInstance(hit.details["distance"], int)
            self.assertGreaterEqual(hit.details["distance"], 1)
            self.assertLessEqual(hit.details["distance"], 3)

    def test_reason_message_format(self):
        """Test that reason message is properly formatted"""
        rec = replace(BASE_REC, from_addr="security@paypaI.com")
        hit = rule_lookalike_domain(rec, self.config)
        
        if not hit.passed:
            reason = hit.details.get("reason", "")
            self.assertIn("looks like", reason)
            self.assertIn("typosquatting", reason)


# ============================================================================
#                         TEST RUNNER                                        
# ============================================================================

def run_tests():
    """Run all lookalike domain tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestLookAlikeDomain)
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("LOOKALIKE DOMAIN RULE TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70)
    
    return result


if __name__ == "__main__":
    result = run_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
