# PhishGuard Detection Engine - Simplified Pipeline Integration
#
# This module provides a simplified interface to the pipeline system
# for analyzing emails and determining if they are safe, suspicious, or phishing attempts.
#
# Key Components:
# - PhishingDetector: Simplified wrapper around pipeline functions
# - Direct integration with pipeline/evaluate.py
# - Clean batch processing capabilities
import json
import os
from typing import Dict, List, Any, Optional
from pathlib import Path

# PhishGuard components
from phishguard.schema import EmailRecord, RuleHit
from phishguard.pipeline.evaluate import build_email_record, evaluate_email_file
from phishguard.scoring.aggregate import evaluate_email
from phishguard.config import load_config
from phishguard.rules import RULES
from phishguard.ingestion.loaders import iterate_emails
from email.message import EmailMessage

# Storage system for saving analysis results
try:
    from phishguard.storage.storage import create_report_manager
    STORAGE_AVAILABLE = True
except ImportError:
    STORAGE_AVAILABLE = False

#====================================
#    Simplified Phishing Detector    =
#====================================
class PhishingDetector:
    
    def __init__(self, config_path: Optional[str] = None):
        # Load detection rules and configuration
        self.config = load_config(config_path)
        
        # Optional report manager for saving results
        if STORAGE_AVAILABLE:
            try:
                self.report_manager = create_report_manager()
            except Exception:
                self.report_manager = None
        else:
            self.report_manager = None

    # ========================================================================
    #                      Main Analysis Functions                           =
    # ========================================================================

    def analyze_email(self, sender: str, subject: str, body: str) -> tuple[EmailRecord, float, List[RuleHit]]:
        """
        Analyze a single email for phishing indicators using the pipeline.
        
        Args:
            sender: Email address of the sender
            subject: Subject line of the email
            body: Text content of the email body
            
        Returns:
            Tuple containing:
            - EmailRecord: Structured email data
            - float: Total risk score
            - List[RuleHit]: Details of each security rule result
        """
        # Create EmailMessage object from user input
        email_msg = EmailMessage()
        email_msg['From'] = sender
        email_msg['Subject'] = subject
        email_msg.set_content(body)
        
        # Use pipeline to build email record
        email_record = build_email_record(email_msg)
        
        # Use pipeline to evaluate email
        rule_hits, total_score, classification = evaluate_email(email_record, RULES, self.config)
        
        # Save results if storage is available
        self._save_analysis_results(sender, subject, body, classification)
        
        return email_record, total_score, rule_hits

    def analyze_batch_emails(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze multiple emails from a file or folder using the pipeline.
        
        Args:
            file_path: Path to email file or folder containing email files
            
        Returns:
            Dictionary containing results and summary statistics
        """
        try:
            results = []
            email_count = 0
            
            # Process each email in the file/folder using pipeline components
            for path, email_msg in iterate_emails(file_path):
                try:
                    # Use pipeline to build email record
                    email_record = build_email_record(email_msg)
                    
                    # Use pipeline to evaluate email
                    rule_hits, total_score, classification = evaluate_email(email_record, RULES, self.config)
                    
                    # Store results
                    email_count += 1
                    analysis_result = {
                        'email_record': email_record,
                        'total_score': total_score,
                        'rule_hits': rule_hits,
                        'classification': classification,
                        'email_number': email_count,
                        'filename': str(path)
                    }
                    results.append(analysis_result)
                    
                    # Save to report manager if available
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

    # ========================================================================
    #                         Helper Functions                               =
    # ========================================================================

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
                threat_level = threat_mapping.get(classification.upper(), 'Medium')
                
                # Save to report manager
                self.report_manager.add_email_report(sender, subject, body, threat_level)
                
            except Exception:
                pass  # Continue if storage fails

    def _generate_batch_summary(self, results: List[Dict]) -> Dict[str, Any]:
        """Generate summary statistics from batch results"""
        total_emails = len(results)
        
        # Count classifications
        safe_count = sum(1 for r in results if r['classification'].upper() == 'SAFE')
        suspicious_count = sum(1 for r in results if r['classification'].upper() == 'SUSPICIOUS')
        phishing_count = sum(1 for r in results if r['classification'].upper() == 'PHISHING')
        
        return {
            'total_emails': total_emails,
            'safe_count': safe_count,
            'suspicious_count': suspicious_count,
            'phishing_count': phishing_count,
            'safe_percentage': (safe_count / total_emails) * 100 if total_emails > 0 else 0,
            'suspicious_percentage': (suspicious_count / total_emails) * 100 if total_emails > 0 else 0,
            'phishing_percentage': (phishing_count / total_emails) * 100 if total_emails > 0 else 0
        }