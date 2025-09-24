# PhishGuard Detection Engine - Core email analysis
import json
import os
from typing import Dict, List, Any, Optional
from pathlib import Path

# PhishGuard components
from phishguard.schema import EmailRecord, RuleHit, Severity
from phishguard.scoring import evaluate_email
from phishguard.config import load_config
from phishguard.ingestion.loaders import iterate_emails
from phishguard.features.extractors import extract_urls
from phishguard.normalize.parse_mime import normalize_header, decode_address, extract_body

# Storage system for saving analysis results
try:
    from phishguard.storage.storage import create_report_manager
    STORAGE_AVAILABLE = True
except ImportError:
    STORAGE_AVAILABLE = False

#====================================
#    Phishing Detector Engine       =
#====================================
class PhishingDetector:
    
    def __init__(self, config_path: Optional[str] = None):
        # Load detection rules and configuration
        self.config = load_config(config_path)
        
        # Optional threat intelligence storage
        self.threat_intelligence = None
        self._load_threat_intelligence()
        
        # Optional report manager for saving results
        if STORAGE_AVAILABLE:
            try:
                self.report_manager = create_report_manager()
            except Exception:
                self.report_manager = None
        else:
            self.report_manager = None

    def _load_threat_intelligence(self):
        """Load additional threat data if available"""
        try:
            intel_path = Path("data/threat_intelligence.json")
            if intel_path.exists():
                with intel_path.open('r') as f:
                    self.threat_intelligence = json.load(f)
        except Exception:
            self.threat_intelligence = None

    # ========================================================================
    #                      Main Analysis Functions                           =
    # ========================================================================

    def analyze_email(self, sender: str, subject: str, body: str) -> tuple[EmailRecord, float, List[RuleHit]]:
        # Convert raw email to structured format
        email_record = self._create_email_record(sender, subject, body)
        
        # Run security analysis
        total_score, rule_hits = evaluate_email(email_record, self.config)
        
        # Save results if possible
        classification = self._get_classification(total_score)
        self._save_analysis_results(sender, subject, body, classification)
        
        return email_record, total_score, rule_hits

    def analyze_batch_emails(self, file_path: str) -> Dict[str, Any]:
        # Analyze multiple emails from a file or folder
        try:
            results = []
            email_count = 0
            
            # Process each email in the file/folder
            for path, email_msg in iterate_emails(file_path):
                try:
                    # Convert to structured format
                    email_record = self._convert_email_message_to_record(email_msg)
                    
                    # Analyze email
                    total_score, rule_hits = evaluate_email(email_record, self.config)
                    
                    # Store raw results for GUI formatting
                    email_count += 1
                    analysis_result = {
                        'email_record': email_record,
                        'total_score': total_score,
                        'rule_hits': rule_hits,
                        'email_number': email_count
                    }
                    results.append(analysis_result)
                    
                    # Save to report manager if available
                    classification = self._get_classification(total_score)
                    self._save_analysis_results(
                        email_record.from_addr, email_record.subject, 
                        email_record.body_text or '', classification
                    )
                    
                except Exception:
                    continue  # Skip problematic emails
            
            # Generate summary statistics
            if not results:
                return {'error': 'No valid emails found in file'}
            
            summary = self._generate_batch_summary(results)
            return {'results': results, 'summary': summary}
            
        except Exception as e:
            return {'error': f'Failed to process batch file: {str(e)}'}

    def generate_report(self, batch_results: Dict[str, Any], output_file: str) -> bool:
        """Generate text report from batch analysis results"""
        try:
            with open(output_file, 'w') as f:
                # Write header
                f.write("PHISHGUARD BATCH ANALYSIS REPORT\n")
                f.write("=" * 50 + "\n\n")
                
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
                    
                    # Add rule details if available
                    if result.get('keywords', {}).get('found'):
                        f.write(f"  Suspicious Keywords: {', '.join(result['keywords']['found'][:3])}\n")
                    if result.get('urls', {}).get('suspicious'):
                        f.write(f"  Suspicious URLs: {len(result['urls']['suspicious'])}\n")
            
            return True
            
        except Exception:
            return False

    # ========================================================================
    #                         Helper Functions                               =
    # ========================================================================

    def _create_email_record(self, sender: str, subject: str, body: str) -> EmailRecord:
        """Convert raw email input to structured EmailRecord"""
        # Extract URLs from email body
        urls_list, url_display_pairs = extract_urls(body, None)
        
        # Create structured email record
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

    def _convert_email_message_to_record(self, email_msg) -> EmailRecord:
        """Convert email message from file to EmailRecord"""
        # Extract headers and addresses
        headers_dict = normalize_header(email_msg)
        subject = headers_dict.get('subject', '')
        from_display, from_addr, reply_to_addr = decode_address(email_msg)
        
        # Extract body content
        body_text, body_html = extract_body(email_msg)
        
        # Find URLs in content
        urls_list, url_display_pairs = extract_urls(body_text, body_html)
        
        # Create structured record
        return EmailRecord(
            from_display=from_display,
            from_addr=from_addr,
            reply_to_addr=reply_to_addr,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            urls=urls_list,
            url_display_pairs=url_display_pairs,
            attachments=[],
            headers=dict(email_msg.items()),
            spf_pass=None,
            dkim_pass=None,
            dmarc_pass=None
        )

    def _get_classification(self, total_score: float) -> str:
        """Convert risk score to classification"""
        thresholds = self.config.get('thresholds', {})
        safe_max = thresholds.get('safe_max', 2.0)
        phishing_min = thresholds.get('phishing_min', 2.0)
        
        if total_score <= safe_max:
            return "SAFE"
        elif total_score >= phishing_min:
            return "PHISHING"
        else:
            return "SUSPICIOUS"

    def _save_analysis_results(self, sender: str, subject: str, body: str, classification: str):
        """Save analysis results to report manager if available"""
        if self.report_manager:
            try:
                # Convert classification to threat level format
                threat_mapping = {
                    'SAFE': 'Low',
                    'SUSPICIOUS': 'Medium', 
                    'PHISHING': 'Critical'
                }
                threat_level = threat_mapping.get(classification, 'Medium')
                
                # Save to report manager
                self.report_manager.add_email_report(sender, subject, body, threat_level)
                
            except Exception:
                pass  # Continue if storage fails

    def _generate_batch_summary(self, results: List[Dict]) -> Dict[str, Any]:
        """Generate summary statistics from batch results"""
        total_emails = len(results)
        thresholds = self.config.get('thresholds', {})
        safe_max = thresholds.get('safe_max', 2.0)
        phishing_min = thresholds.get('phishing_min', 2.0)
        
        # Count classifications
        safe_count = 0
        suspicious_count = 0
        phishing_count = 0
        
        for result in results:
            score = result['total_score']
            if score <= safe_max:
                safe_count += 1
            elif score >= phishing_min:
                phishing_count += 1
            else:
                suspicious_count += 1
        
        return {
            'total_emails': total_emails,
            'safe_count': safe_count,
            'suspicious_count': suspicious_count,
            'phishing_count': phishing_count,
            'safe_percentage': (safe_count / total_emails) * 100,
            'suspicious_percentage': (suspicious_count / total_emails) * 100,
            'phishing_percentage': (phishing_count / total_emails) * 100
        }