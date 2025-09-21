"""
PhishingDetector wrapper for GUI integration

This module provides a simplified interface to the PhishGuard rule-based detection system
for use by the GUI application. It wraps the existing scoring and rules modules to provide
a clean API that matches what the UI expects.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

from phishguard.schema import EmailRecord, RuleHit, Severity
from phishguard.scoring import evaluate_email
from phishguard.config import load_config
from phishguard.ingestion.loaders import iterate_emails
from phishguard.features.extractors import extract_urls
from phishguard.normalize.parse_mime import parse_email_to_record


class PhishingDetector:
    """
    Main PhishingDetector class for GUI integration
    
    This class provides a simplified interface to the PhishGuard detection system,
    designed to be compatible with the existing UI code while leveraging the
    actual PhishGuard rule-based detection pipeline.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the detector with configuration"""
        self.config = load_config(config_path)
        self.threat_intelligence = None
        
        # Load threat intelligence if available
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
            print(f"Could not load threat intelligence: {e}")
            self.threat_intelligence = None
    
    def analyze_email(self, sender: str, subject: str, body: str) -> Dict[str, Any]:
        """
        Analyze a single email and return results in GUI-compatible format
        
        Args:
            sender: Email sender address
            subject: Email subject line
            body: Email body content
            
        Returns:
            Dictionary with analysis results compatible with UI expectations
        """
        # Convert input to EmailRecord
        email_record = self._create_email_record(sender, subject, body)
        
        # Run the PhishGuard evaluation
        total_score, rule_hits = evaluate_email(email_record, self.config)
        
        # Convert results to GUI-compatible format
        return self._format_results(email_record, total_score, rule_hits)
    
    def _create_email_record(self, sender: str, subject: str, body: str) -> EmailRecord:
        """Convert raw email input to EmailRecord object"""
        # Extract URLs from body
        urls = extract_urls(body)
        
        # Create basic email record
        # Note: For GUI input, we don't have full headers/auth info
        return EmailRecord(
            from_display=sender.split('@')[0] if '@' in sender else sender,
            from_addr=sender,
            reply_to_addr=None,
            subject=subject,
            body_text=body,
            body_html=None,
            urls=urls,
            url_display_pairs=[(url, url) for url in urls],
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
                    # Convert EmailMessage to EmailRecord
                    email_record = parse_email_to_record(email_msg)
                    
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
                    
                    results.append(analysis_result)
                    
                except Exception as e:
                    print(f"Error processing email {email_count + 1}: {e}")
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
            print(f"Error generating report: {e}")
            return False
