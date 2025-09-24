
# ============================================================================
#                              IMPORTS
# ============================================================================
import json                            # For loading configuration files
import os                             # For file operations
from datetime import datetime          # For timestamps in reports
from typing import Dict, List, Any, Optional  # For type hints (helps catch errors)
from pathlib import Path              # For handling file paths

# PhishGuard core components
from phishguard.schema import EmailRecord, RuleHit, Severity  # Data structures
from phishguard.scoring import evaluate_email               # Main analysis engine
from phishguard.config import load_config                   # Configuration loader
from phishguard.ingestion.loaders import iterate_emails     # Email file loader
from phishguard.features.extractors import extract_urls     # URL extractor

# Your friend's email parsing functions (clean and simple!)
from phishguard.normalize.parse_mime import normalize_header, decode_address, extract_body

# Storage system for saving analysis results
try:
    from phishguard.storage.storage import create_report_manager
    STORAGE_AVAILABLE = True
except ImportError:
    STORAGE_AVAILABLE = False


# ============================================================================
#                           MAIN DETECTOR CLASS
# ============================================================================

class PhishingDetector:
    """
    ==========================================================================
                            PHISHING DETECTION ENGINE
    ==========================================================================
    
    This is the main class that analyzes emails for phishing threats.
    
    WHAT IT DOES:
    - Takes email data and runs it through security rules
    - Checks for suspicious keywords, URLs, domains, etc.
    - Returns a simple result: SAFE, SUSPICIOUS, or PHISHING
    - Provides detailed explanations for each decision
    
    THINK OF IT LIKE:
    A security guard that checks every email and decides if it's safe or dangerous.
    
    HOW TO USE:
    1. Create detector: detector = PhishingDetector()
    2. Analyze email: result = detector.analyze_email(sender, subject, body)
    3. Read result: result['classification'] gives you SAFE/SUSPICIOUS/PHISHING
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        INITIALIZE THE PHISHING DETECTOR
        
        This sets up the detector with all the rules and configurations
        needed to analyze emails for phishing threats.
        
        Args:
            config_path: Optional path to config file (uses default if None)
        """
        # STEP 1: Load the configuration (rules, thresholds, etc.)
        self.config = load_config(config_path)  # This loads all the detection rules
        
        # STEP 2: Initialize threat intelligence storage
        self.threat_intelligence = None  # Advanced threat data (optional)
        
        # STEP 3: Initialize email report manager for saving analysis results
        if STORAGE_AVAILABLE:
            try:
                self.report_manager = create_report_manager()
            except Exception as e:
                self.report_manager = None
        else:
            self.report_manager = None
        
        # STEP 4: Try to load additional threat intelligence
        self._load_threat_intelligence()
    
    def _load_threat_intelligence(self):
        """Load threat intelligence data if available"""
        # For now, we'll use the static configuration
        # This can be extended to load dynamic threat intelligence
        try:
            intel_path = Path("data/threat_intelligence.json")
            if intel_path.exists():
                with intel_path.open('r') as f:
                    self.threat_intelligence = json.load(f)
        except Exception as e:
            self.threat_intelligence = None
    
    # ========================================================================
    #                        MAIN ANALYSIS FUNCTIONS
    # ========================================================================
    
    def analyze_email(self, sender: str, subject: str, body: str) -> Dict[str, Any]:
        """
        ANALYZE A SINGLE EMAIL FOR PHISHING THREATS
        
        This is the main function that takes email details and returns
        a security analysis. It's called by the GUI when users click "Analyze Email".
        
        PROCESS OVERVIEW:
        1. Take the raw email data (sender, subject, body)
        2. Convert it into a structured format our rules can understand
        3. Run it through all our security checks (keywords, URLs, domains, etc.)
        4. Calculate a risk score based on what we found
        5. Decide if it's SAFE, SUSPICIOUS, or PHISHING
        6. Format the results so the GUI can display them nicely
        7. Save the results for future reference
        
        THINK OF IT LIKE A SECURITY CHECKPOINT:
        - The email comes in with basic information
        - We check it against our security rules (like a checklist)
        - We give it a risk score (like a threat level)
        - We make a final decision about safety
        - We tell the user what we found and why
        
        Args:
            sender: The email address that sent this email
                   Example: "security@paypal.com" or "suspicious@fake-bank.com"
            subject: The subject line of the email
                    Example: "Your account has been suspended" or "Urgent action required"
            body: The main content/text of the email
                 Example: "Click here to verify your account: http://fake-link.com"
                 
        Returns:
            A dictionary (like a report card) containing:
            {
                'classification': The final verdict - 'SAFE', 'SUSPICIOUS', or 'PHISHING'
                'final_score': A number showing how risky this email is (higher = more dangerous)
                'whitelist': Results about whether the sender domain is trusted
                'keywords': Information about suspicious words found in the email
                'spoofing': Results about whether the sender might be fake/impersonating someone
                'urls': Analysis of any links found in the email
            }
        """
        
        # STEP 1: PREPARE THE EMAIL DATA
        # ==============================
        # Take the raw email information and convert it into a structured format
        # that our security rules can understand and analyze properly
        print(f"Step 1: Converting email data into analysis format...")
        email_record = self._create_email_record(sender, subject, body)
        print(f"  ✓ Email record created for analysis")
        
        # STEP 2: RUN SECURITY ANALYSIS
        # =============================
        # Pass the structured email through all our security rules
        # This checks for things like:
        # - Suspicious keywords ("urgent", "verify now", "click here")
        # - Dangerous URLs (shortened links, suspicious domains)
        # - Domain spoofing (fake versions of real companies)
        # - Sender reputation (is this a trusted domain?)
        print(f"Step 2: Running email through security rules...")
        total_score, rule_hits = evaluate_email(email_record, self.config)
        print(f"  ✓ Security analysis complete. Risk score: {total_score}")
        
        # STEP 3: INTERPRET THE RESULTS
        # =============================
        # Take the raw security rule results and format them into
        # something the GUI can display in a user-friendly way
        print(f"Step 3: Formatting results for display...")
        results = self._format_results(email_record, total_score, rule_hits)
        
        # Determine what the final classification means
        classification = results['classification']
        if classification == 'SAFE':
            print(f"  ✓ VERDICT: Email appears to be legitimate and safe")
        elif classification == 'SUSPICIOUS':
            print(f"  ⚠ VERDICT: Email has suspicious characteristics - use caution")
        else:  # PHISHING
            print(f"  🚨 VERDICT: Email appears to be a phishing attempt - avoid!")
        
        # STEP 4: SAVE RESULTS FOR FUTURE REFERENCE
        # =========================================
        # If we have a report manager available, save this analysis
        # so we can track patterns and generate reports later
        if self.report_manager:
            print(f"Step 4: Saving analysis results...")
            try:
                # Convert our classification to the format the report manager expects
                threat_level = self._convert_classification_to_threat_level(classification)
                
                # Store the email analysis in our database/file system
                self.report_manager.add_email_report(sender, subject, body, threat_level)
                print(f"  ✓ Results saved to report manager")
                
            except Exception as e:
                # If saving fails, that's okay - we don't want to break the analysis
                print(f"  ⚠ Could not save results (continuing anyway): {e}")
                pass
        else:
            print(f"Step 4: No report manager available - skipping save")
        
        # STEP 5: RETURN THE FINAL ANALYSIS
        # =================================
        print(f"Analysis complete! Returning results to GUI...")
        return results
    
    def _convert_classification_to_threat_level(self, classification: str) -> str:
        """
        CONVERT PHISHGUARD CLASSIFICATION TO THREAT LEVEL
        
        This converts our internal classification (SAFE, SUSPICIOUS, PHISHING)
        to the threat level format used by the report manager.
        
        Args:
            classification: PhishGuard classification (SAFE, SUSPICIOUS, PHISHING)
            
        Returns:
            Threat level string (Low, Medium, High, Critical)
        """
        classification_mapping = {
            'SAFE': 'Low',
            'SUSPICIOUS': 'Medium', 
            'PHISHING': 'Critical'
        }
        
        return classification_mapping.get(classification, 'Medium')
    
    # ========================================================================
    #                        EMAIL CONVERSION FUNCTIONS
    # ========================================================================
    
    def _convert_email_message_to_record(self, email_msg) -> EmailRecord:
        """
        CONVERT EMAIL FILE TO STRUCTURED FORMAT (USING YOUR FRIEND'S CODE!)
        
        This function takes an email loaded from a file and converts it
        into a structured format that our analysis engine can understand.
        
        USES YOUR FRIEND'S FUNCTIONS:
        - normalize_header() - Clean up email headers
        - decode_address() - Extract sender information
        - extract_body() - Get email content
        
        Args:
            email_msg: Raw email message from file
            
        Returns:
            EmailRecord: Structured email data ready for analysis
        """
        # STEP 1: Extract and clean headers using friend's function
        headers_dict = normalize_header(email_msg)
        subject = headers_dict.get('subject', '')
        
        # STEP 2: Extract sender/reply addresses using friend's function
        from_display, from_addr, reply_to_addr = decode_address(email_msg)
        
        # STEP 3: Extract email body content using friend's function
        body_text, body_html = extract_body(email_msg)
        
        # STEP 4: Find URLs in the email content
        urls_list, url_display_pairs = extract_urls(body_text, body_html)
        
        # STEP 5: Create structured email record for analysis
        return EmailRecord(
            from_display=from_display,     # Display name (e.g., "John Smith")
            from_addr=from_addr,           # Email address (e.g., "john@example.com")
            reply_to_addr=reply_to_addr,   # Reply-to address (if different)
            subject=subject,               # Email subject line
            body_text=body_text,           # Plain text content
            body_html=body_html,           # HTML content (if any)
            urls=urls_list,                # List of URLs found
            url_display_pairs=url_display_pairs,  # URL and display text pairs
            attachments=[],                # File attachments (simplified for now)
            headers=dict(email_msg.items()),       # All email headers
            spf_pass=None,                 # Email authentication results
            dkim_pass=None,                # (simplified for now)
            dmarc_pass=None
        )
    
    def _create_email_record(self, sender: str, subject: str, body: str) -> EmailRecord:
        """Convert raw email input to EmailRecord object"""
        # Extract URLs from body
        urls_list, url_display_pairs = extract_urls(body, None)  # No HTML version for manual input
        
        # Create basic email record
        # Note: For GUI input, we don't have full headers/auth info
        return EmailRecord(
            from_display=sender.split('@')[0] if '@' in sender else sender,
            from_addr=sender,
            reply_to_addr=None,
            subject=subject,
            body_text=body,
            body_html=None,
            urls=urls_list,
            url_display_pairs=url_display_pairs,
            attachments=[],
            headers={'From': sender, 'Subject': subject},
            spf_pass=None,
            dkim_pass=None,
            dmarc_pass=None
        )
    
    def _format_results(self, email_record: EmailRecord, total_score: float, rule_hits: List[RuleHit]) -> Dict[str, Any]:
        """Format PhishGuard results for GUI display"""
        
        # Determine classification based on thresholds
        thresholds = self.config.get('thresholds', {})
        safe_max = thresholds.get('safe_max', 2.0)
        phishing_min = thresholds.get('phishing_min', 2.0)
        
        if total_score <= safe_max:
            classification = "SAFE"
        elif total_score >= phishing_min:
            classification = "PHISHING"
        else:
            classification = "SUSPICIOUS"
        
        # Extract rule-specific results
        whitelist_hit = next((hit for hit in rule_hits if hit.rule_name == 'whitelist'), None)
        keywords_hit = next((hit for hit in rule_hits if hit.rule_name == 'keywords'), None)
        urls_hit = next((hit for hit in rule_hits if hit.rule_name == 'url_redflags'), None)
        lookalike_hit = next((hit for hit in rule_hits if hit.rule_name == 'lookalike_domain'), None)
        
        # Format whitelist results
        whitelist_results = {
            'is_safe': whitelist_hit.passed if whitelist_hit else False,
            'score': abs(whitelist_hit.score_delta) if whitelist_hit else 0.0
        }
        
        # Format keyword results
        keywords_found = []
        if keywords_hit and not keywords_hit.passed:
            # Extract keywords from details if available
            details = keywords_hit.details or {}
            # This is a simplified extraction - you may need to adjust based on actual keyword rule implementation
            keywords_found = list(self.config.get('rules', {}).get('keywords', {}).get('weights', {}).keys())[:5]
        
        keywords_results = {
            'found': keywords_found,
            'score': keywords_hit.score_delta if keywords_hit else 0.0
        }
        
        # Format spoofing/lookalike results
        spoofing_results = {
            'detected': lookalike_hit and not lookalike_hit.passed,
            'reason': lookalike_hit.details.get('reason', 'Domain similarity detected') if lookalike_hit and not lookalike_hit.passed else '',
            'score': lookalike_hit.score_delta if lookalike_hit else 0.0
        }
        
        # Format URL results
        suspicious_urls = []
        if urls_hit and not urls_hit.passed:
            # Extract suspicious URLs from the email record
            for url in email_record.urls:
                suspicious_urls.append(f"{url} (suspicious patterns detected)")
        
        url_results = {
            'suspicious': suspicious_urls,
            'score': urls_hit.score_delta if urls_hit else 0.0
        }
        
        return {
            'classification': classification,
            'final_score': total_score,
            'whitelist': whitelist_results,
            'keywords': keywords_results,
            'spoofing': spoofing_results,
            'urls': url_results,
            'rule_hits': rule_hits,  # Include raw rule hits for detailed analysis
            'max_score': 50  # Approximate max score for percentage calculations
        }
    
    def analyze_batch_emails(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze multiple emails from a file
        
        Args:
            file_path: Path to file containing emails
            
        Returns:
            Dictionary with batch analysis results
        """
        try:
            results = []
            email_count = 0
            
            # Use PhishGuard's email loading system
            for path, email_msg in iterate_emails(file_path):
                try:
                    # Convert EmailMessage to EmailRecord using friend's functions
                    email_record = self._convert_email_message_to_record(email_msg)
                    
                    # Run analysis
                    total_score, rule_hits = evaluate_email(email_record, self.config)
                    
                    # Format results
                    analysis_result = self._format_results(email_record, total_score, rule_hits)
                    
                    # Add email metadata
                    email_count += 1
                    analysis_result['email_number'] = email_count
                    analysis_result['email_data'] = {
                        'sender': email_record.from_addr,
                        'subject': email_record.subject,
                        'body_length': len(email_record.body_text or '')
                    }
                    
                    # Save individual email analysis to report manager
                    if self.report_manager:
                        try:
                            threat_level = self._convert_classification_to_threat_level(analysis_result['classification'])
                            self.report_manager.add_email_report(
                                email_record.from_addr, email_record.subject, 
                                email_record.body_text or '', threat_level)
                        except Exception as e:
                            pass  # Continue if storage fails
                    
                    results.append(analysis_result)
                    
                except Exception as e:
                    continue
            
            # Generate summary statistics
            total_emails = len(results)
            if total_emails == 0:
                return {'error': 'No valid emails found in file'}
            
            safe_count = len([r for r in results if r['classification'] == 'SAFE'])
            suspicious_count = len([r for r in results if r['classification'] == 'SUSPICIOUS'])
            phishing_count = len([r for r in results if r['classification'] == 'PHISHING'])
            
            summary = {
                'total_emails': total_emails,
                'safe_count': safe_count,
                'suspicious_count': suspicious_count,
                'phishing_count': phishing_count,
                'safe_percentage': (safe_count / total_emails) * 100,
                'suspicious_percentage': (suspicious_count / total_emails) * 100,
                'phishing_percentage': (phishing_count / total_emails) * 100
            }
            
            return {
                'results': results,
                'summary': summary,
                'processed_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {'error': f'Failed to process batch file: {str(e)}'}
    
    def generate_report(self, batch_results: Dict[str, Any], output_file: str) -> bool:
        """
        Generate a detailed report from batch analysis results
        
        Args:
            batch_results: Results from analyze_batch_emails
            output_file: Path to save the report
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(output_file, 'w') as f:
                f.write("PHISHGUARD BATCH ANALYSIS REPORT\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Write summary
                summary = batch_results.get('summary', {})
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-" * 20 + "\n")
                f.write(f"Total Emails Analyzed: {summary.get('total_emails', 0)}\n")
                f.write(f"Safe Emails: {summary.get('safe_count', 0)} ({summary.get('safe_percentage', 0):.1f}%)\n")
                f.write(f"Suspicious Emails: {summary.get('suspicious_count', 0)} ({summary.get('suspicious_percentage', 0):.1f}%)\n")
                f.write(f"Phishing Emails: {summary.get('phishing_count', 0)} ({summary.get('phishing_percentage', 0):.1f}%)\n\n")
                
                # Write detailed results
                f.write("DETAILED ANALYSIS\n")
                f.write("-" * 20 + "\n")
                
                for result in batch_results.get('results', []):
                    f.write(f"\nEmail #{result['email_number']}: {result['classification']}\n")
                    f.write(f"  From: {result['email_data']['sender']}\n")
                    f.write(f"  Subject: {result['email_data']['subject']}\n")
                    f.write(f"  Risk Score: {result['final_score']}\n")
                    
                    # Add rule details
                    if result.get('keywords', {}).get('found'):
                        f.write(f"  Suspicious Keywords: {', '.join(result['keywords']['found'][:3])}\n")
                    if result.get('urls', {}).get('suspicious'):
                        f.write(f"  Suspicious URLs: {len(result['urls']['suspicious'])}\n")
                
            return True
            
        except Exception as e:
            return False
