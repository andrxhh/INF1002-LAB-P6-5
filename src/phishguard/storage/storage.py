"""
Email storage and reporting system for PhishGuard
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any


class EmailReportManager:
    """
    Simple email report manager that stores analysis results in JSON format.
    Keeps track of emails with their threat levels for security monitoring.
    """
    
    def __init__(self, filename: str = "email_analysis_reports.json"):
        """Initialize the report manager with a storage file"""
        self.filename = filename
        self.emails = []
        self._load_existing_data()
    
    def _load_existing_data(self):
        """Load existing email reports from file if it exists"""
        try:
            if os.path.exists(self.filename):
                with open(self.filename, 'r') as f:
                    data = json.load(f)
                    self.emails = data.get('emails', [])
                print(f"Loaded {len(self.emails)} existing email reports")
            else:
                self.emails = []
        except Exception as e:
            print(f"Could not load existing data: {e}")
            self.emails = []
    
    def add_email_report(self, sender: str, subject: str, body: str, 
                        threat_level: str, analysis_details: Dict = None) -> bool:
        """Add a new email analysis report"""
        try:
            email_report = {
                'fromEmail': sender,
                'Subject': subject,
                'Body': body[:500] + "..." if len(body) > 500 else body,
                'threatLevel': threat_level,
                'timestamp': datetime.now().isoformat(),
                'analysis_details': analysis_details or {}
            }
            
            self.emails.append(email_report)
            self._save_to_file()
            return True
        except Exception as e:
            print(f"Failed to save email report: {e}")
            return False
    
    def bulk_add(self, email_list: List[Dict]) -> int:
        """Add multiple email reports at once"""
        added_count = 0
        for email_data in email_list:
            try:
                if 'timestamp' not in email_data:
                    email_data['timestamp'] = datetime.now().isoformat()
                self.emails.append(email_data)
                added_count += 1
            except Exception as e:
                print(f"Could not add email: {e}")
                continue
        
        if added_count > 0:
            self._save_to_file()
        return added_count
    
    def _save_to_file(self):
        """Save all email reports to the JSON file"""
        try:
            report_data = {
                'metadata': {
                    'created': datetime.now().isoformat(),
                    'total_emails': len(self.emails),
                    'format_version': '1.0'
                },
                'emails': self.emails
            }
            
            with open(self.filename, 'w') as f:
                json.dump(report_data, f, indent=2)
        except Exception as e:
            print(f"Could not save to file: {e}")
    
    def filter_by_threat(self, threat_level: str) -> List[Dict]:
        """Filter emails by threat level"""
        return [email for email in self.emails 
                if email.get('threatLevel', '').lower() == threat_level.lower()]
    
    def get_threat_statistics(self) -> Dict[str, int]:
        """Get statistics about threat levels"""
        stats = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
        for email in self.emails:
            threat_level = email.get('threatLevel', 'Unknown')
            if threat_level in stats:
                stats[threat_level] += 1
        return stats
    
    def show_stats(self):
        """Display threat statistics"""
        stats = self.get_threat_statistics()
        total = len(self.emails)
        
        print(f"\nEmail Threat Statistics")
        print(f"=====================")
        print(f"Total Emails: {total}")
        if total > 0:
            for level, count in stats.items():
                percentage = (count / total) * 100
                print(f"{level}: {count} ({percentage:.1f}%)")
    
    def print_emails(self, emails: List[Dict] = None):
        """Print email reports to console"""
        if emails is None:
            emails = self.emails
        
        if not emails:
            print("No emails to display.")
            return
        
        print(f"\n--- EMAIL REPORTS ({len(emails)} emails) ---")
        
        for i, email in enumerate(emails, 1):
            print(f"\n{i}. From: {email['fromEmail']}")
            print(f"   Subject: {email['Subject']}")
            print(f"   Body: {email['Body']}")
            print(f"   Threat: {email['threatLevel']}")
            print(f"   Time: {email['timestamp']}")


def create_sample_data():
    """Generate some test emails for demo purposes"""
    
    # mix of legit and suspicious emails
    samples = [
        {
            'fromEmail': 'paypal-noreply@paypal.com',
            'Subject': 'Please verify your account',
            'Body': 'Dear valued customer, we noticed some unusual activity on your PayPal account. Please click here to verify your identity within 24 hours or your account will be suspended.',
            'threatLevel': 'High'
        },
        {
            'fromEmail': 'orders@amazon.com', 
            'Subject': 'Your package has shipped!',
            'Body': 'Good news! Your order #AMZ-12345 has been shipped via UPS. Track your package with tracking number 1Z999AA1234567890. Estimated delivery: 2-3 business days.',
            'threatLevel': 'Low'
        },
        {
            'fromEmail': 'security-alert@chase.com',
            'Subject': 'URGENT - Suspicious login attempt',
            'Body': 'We detected a login attempt from an unrecognized device in Nigeria. If this was not you, please secure your account immediately by clicking the link below.',
            'threatLevel': 'Critical'
        },
        {
            'fromEmail': 'daily-digest@reddit.com',
            'Subject': 'Your daily Reddit digest',
            'Body': 'Here are the top posts from your subscribed communities today. Check out what you missed while you were away!',
            'threatLevel': 'Low'
        },
        {
            'fromEmail': 'support@microsoft-team.org',  # suspicious domain
            'Subject': 'Windows Security Update Required',
            'Body': 'Your Windows license will expire in 3 days. Click here to renew and download the latest security patches to protect against malware.',
            'threatLevel': 'Medium'
        },
        {
            'fromEmail': 'sarah.johnson@acmecorp.com',
            'Subject': 'Re: Quarterly budget meeting',
            'Body': 'Hi everyone, the budget meeting has been moved to Thursday 3pm. Please review the attached documents before the meeting. Thanks!',
            'threatLevel': 'Low'
        },
        {
            'fromEmail': 'winner-notification@internationallottery.biz',
            'Subject': 'You have won $500,000 USD!!!',
            'Body': 'CONGRATULATIONS!!! You have been randomly selected to receive $500,000 from the International Email Lottery. Send us your bank details to claim your prize!',
            'threatLevel': 'Critical'
        },
    ]
    
    return samples


# Helper function for easy integration
def create_report_manager(filename: str = "email_analysis_reports.json") -> EmailReportManager:
    """Create and return an EmailReportManager instance"""
    return EmailReportManager(filename)


# Main execution
if __name__ == "__main__":
    print("Email Report Manager")
    print("===================")
    
    # set up the manager
    manager = EmailReportManager()
    
    # add some test data
    print("\nAdding sample email data...")
    sample_emails = create_sample_data()
    added = manager.bulk_add(sample_emails)
    print(f"Added {added} emails")
    
    # show some stats
    manager.show_stats()
    
    # display the emails
    print("\nAll emails:")
    manager.print_emails()
    
    # show just the dangerous ones
    print("\n=== HIGH RISK EMAILS ===")
    dangerous = manager.filter_by_threat('High') + manager.filter_by_threat('Critical')
    if dangerous:
        for email in dangerous:
            print(f"⚠️  {email['fromEmail']}: {email['Subject']}")
    else:
        print("No high-risk emails found")
    
    print(f"\nDone! Check {manager.filename} for the full report.")