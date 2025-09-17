"""
Example showing how to import and use config in PhishGuard rules and tests.

This file demonstrates the recommended patterns for using configuration
throughout your PhishGuard project.
"""

# ========== FOR RULES ==========

# Option 1: Import config functions and load as needed
from phishguard.config import load_config, get_rule_config

def rule_example_with_config_loading(rec, config=None):
    """Example rule that loads config if not provided."""
    if config is None:
        config = load_config()
    
    rule_config = get_rule_config('keywords', config)
    
    # Use config values
    enabled = rule_config.get('enabled', True)
    weights = rule_config.get('weights', {})
    # ... rest of rule logic


# Option 2: Accept config as parameter (recommended for existing rules)
def rule_example_with_config_param(rec, config):
    """Example rule that expects config to be passed in."""
    rule_config = config['rules']['keywords']  # Direct access
    
    # Or use helper function
    # rule_config = get_rule_config('keywords', config)
    
    enabled = rule_config.get('enabled', True)
    if not enabled:
        return None
    
    # ... rest of rule logic


# ========== FOR UNIT TESTS ==========

import unittest
from phishguard.config import load_config, get_rule_config

class ExampleTestCase(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Load config once for all tests in this class."""
        try:
            cls.config = load_config()
        except FileNotFoundError:
            # Fallback config for testing
            cls.config = {
                "rules": {
                    "keywords": {
                        "enabled": True,
                        "weights": {"urgent": 0.8}
                    }
                }
            }
    
    def test_with_loaded_config(self):
        """Test using the loaded config."""
        # Use self.config in your tests
        keywords_config = get_rule_config('keywords', self.config)
        self.assertTrue(keywords_config['enabled'])
    
    def test_with_custom_config(self):
        """Test with a custom config for specific scenarios."""
        custom_config = {
            "rules": {
                "keywords": {
                    "enabled": False,
                    "weights": {}
                }
            }
        }
        
        keywords_config = get_rule_config('keywords', custom_config)
        self.assertFalse(keywords_config['enabled'])


# ========== FOR CLI/APP MODULES ==========

def main_app_example():
    """Example of loading config in main application."""
    from phishguard.config import load_config
    
    # Load config once at startup
    config = load_config()
    
    # Pass config to rules
    # result = rule_keywords(email_record, config)
    
    # Access thresholds
    from phishguard.config import get_thresholds
    thresholds = get_thresholds(config)
    safe_max = thresholds.get('safe_max', 2.0)


if __name__ == "__main__":
    main_app_example()
