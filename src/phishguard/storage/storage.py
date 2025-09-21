#!/usr/bin/env python3
"""
Email Report CSV Manager
Creates and manages a CSV file called "emailReport.csv" with email analysis data.
"""

import csv
import os
from datetime import datetime
from typing import List, Dict, Optional
import random

class EmailReportManager:
    """
    Manages the emailReport.csv file for storing email analysis results.
    
    CSV Structure:
    - fromEmail: Email address of the sender
    - Subject: Email subject line
    - Body: Email body content (truncated for readability)
    - threatLevel: Threat assessment (Low, Medium, High, Critical)
    - timestamp: When the analysis was performed
    """
    
    def __init__(self, csv_filename: str = "emailReport.csv"):
        """
        Initialize the EmailReportManager.
        
        Args:
            csv_filename (str): Name of the CSV file to manage
        """
        self.csv_filename = csv_filename
        self.fieldnames = ['fromEmail', 'Subject', 'Body', 'threatLevel', 'timestamp']
        
        # Create CSV file with headers if it doesn't exist
        self._ensure_csv_exists()
    
    def _ensure_csv_exists(self):
        """Create the CSV file with headers if it doesn't exist."""
        if not os.path.exists(self.csv_filename):
            with open(self.csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
                writer.writeheader()
            print(f"Created new CSV file: {self.csv_filename}")
    
    
    def add_email_record(self, from_email: str, subject: str, body: str, threat_level: str) -> bool:
        """
        Add a new email record to the CSV file.
        
        Args:
            from_email (str): Email address of the sender
            subject (str): Email subject line
            body (str): Email body content
            threat_level (str): Threat level (Low, Medium, High, Critical)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Validate threat level
            valid_threat_levels = ['Low', 'Medium', 'High', 'Critical']
            if threat_level not in valid_threat_levels:
                print(f"Invalid threat level: {threat_level}. Must be one of: {valid_threat_levels}")
                return False
            
            # Truncate body if too long (for CSV readability)
            truncated_body = body[:200] + "..." if len(body) > 200 else body
            
            # Create record
            record = {
                'fromEmail': from_email,
                'Subject': subject,
                'Body': truncated_body,
                'threatLevel': threat_level,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Append to CSV
            with open(self.csv_filename, 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
                writer.writerow(record)
            
            print(f"Added email record: {from_email} - {threat_level} threat")
            return True
            
        except Exception as e:
            print(f"Error adding email record: {str(e)}")
            return False
    
    def add_multiple_records(self, records: List[Dict[str, str]]) -> int:
        """
        Add multiple email records at once.
        
        Args:
            records (List[Dict]): List of email records to add
            
        Returns:
            int: Number of records successfully added
        """
        success_count = 0
        for record in records:
            if self.add_email_record(
                record.get('fromEmail', ''),
                record.get('Subject', ''),
                record.get('Body', ''),
                record.get('threatLevel', 'Low')
            ):
                success_count += 1
        
        return success_count
    
    def read_all_records(self) -> List[Dict[str, str]]:
        """
        Read all records from the CSV file.
        
        Returns:
            List[Dict]: List of all email records
        """
        records = []
        try:
            with open(self.csv_filename, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                records = list(reader)
        except Exception as e:
            print(f"Error reading CSV file: {str(e)}")
        
        return records
    
    def get_records_by_threat_level(self, threat_level: str) -> List[Dict[str, str]]:
        """
        Get all records with a specific threat level.
        
        Args:
            threat_level (str): Threat level to filter by
            
        Returns:
            List[Dict]: Filtered records
        """
        all_records = self.read_all_records()
        return [record for record in all_records if record['threatLevel'] == threat_level]
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get statistics about the email records.
        
        Returns:
            Dict[str, int]: Statistics about threat levels
        """
        records = self.read_all_records()
        stats = {'Total': len(records)}
        
        threat_levels = ['Low', 'Medium', 'High', 'Critical']
        for level in threat_levels:
            stats[level] = len([r for r in records if r['threatLevel'] == level])
        
        return stats
    
    def display_records(self, limit: Optional[int] = None):
        """
        Display records in a formatted way.
        
        Args:
            limit (int, optional): Maximum number of records to display
        """
        records = self.read_all_records()
        
        if limit:
            records = records[:limit]
        
        if not records:
            print("No records found in CSV file.")
            return
        
        print(f"\n{'='*80}")
        print(f"EMAIL REPORT - {len(records)} records")
        print(f"{'='*80}")
        
        for i, record in enumerate(records, 1):
            print(f"\nRecord {i}:")
            print(f"  From: {record['fromEmail']}")
            print(f"  Subject: {record['Subject']}")
            print(f"  Body: {record['Body']}")
            print(f"  Threat Level: {record['threatLevel']}")
            print(f"  Timestamp: {record['timestamp']}")
            print("-" * 40)
    


def generate_example_data() -> List[Dict[str, str]]:
    """
    Generate example email data for testing.
    
    Returns:
        List[Dict]: Example email records
    """
    example_emails = [
        {
            'fromEmail': 'noreply@paypal.com',
            'Subject': 'Urgent: Verify Your Account Immediately',
            'Body': 'Dear Customer, Your PayPal account has been temporarily suspended due to suspicious activity. Please click the link below to verify your account information immediately. Failure to do so will result in permanent account closure.',
            'threatLevel': 'High'
        },
        {
            'fromEmail': 'support@amazon.com',
            'Subject': 'Your Order #12345 has been shipped',
            'Body': 'Hello! Your recent order has been shipped and is on its way. You can track your package using the tracking number: 1Z999AA1234567890. Expected delivery: 2-3 business days.',
            'threatLevel': 'Low'
        },
        {
            'fromEmail': 'security@bankofamerica.com',
            'Subject': 'IMPORTANT: Unusual Login Activity Detected',
            'Body': 'We detected unusual login activity on your account from an unrecognized device. If this was not you, please secure your account immediately by clicking here. Your account may be at risk.',
            'threatLevel': 'Critical'
        },
        {
            'fromEmail': 'newsletter@techcrunch.com',
            'Subject': 'Weekly Tech News Roundup',
            'Body': 'This week in tech: Apple announces new iPhone features, Google releases AI updates, and Tesla reports record sales. Read more about these exciting developments in technology.',
            'threatLevel': 'Low'
        },
        {
            'fromEmail': 'admin@microsoft-security.com',
            'Subject': 'Your Windows License is Expired',
            'Body': 'Your Windows license has expired and your computer is at risk. Download the latest security update immediately to protect your system from malware and viruses.',
            'threatLevel': 'Medium'
        },
        {
            'fromEmail': 'john.smith@company.com',
            'Subject': 'Meeting Reminder - Project Review',
            'Body': 'Hi team, just a reminder about our project review meeting tomorrow at 2 PM in conference room A. Please bring your progress reports and any questions you have.',
            'threatLevel': 'Low'
        },
        {
            'fromEmail': 'lottery@winning-notification.org',
            'Subject': 'CONGRATULATIONS! You Won $1,000,000!',
            'Body': 'Congratulations! You have been selected as the winner of our international lottery. To claim your prize of $1,000,000, please provide your personal information and bank details immediately.',
            'threatLevel': 'Critical'
        },
        {
            'fromEmail': 'hr@linkedin.com',
            'Subject': 'New Job Opportunities for You',
            'Body': 'Based on your profile, we found 5 new job opportunities that match your skills. Check out these positions and apply today to advance your career.',
            'threatLevel': 'Low'
        }
    ]
    
    return example_emails



def main():
    """
    Main function to demonstrate the EmailReportManager functionality.
    """
    print("Email Report CSV Manager - Demo")
    print("=" * 50)
    
    # Create the manager
    manager = EmailReportManager()
    
    # Generate and add example data
    print("\n1. Adding example email data...")
    example_data = generate_example_data()
    success_count = manager.add_multiple_records(example_data)
    print(f"Successfully added {success_count} out of {len(example_data)} records")
    
    # Display statistics
    print("\n2. Email Report Statistics:")
    stats = manager.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Display all records
    print("\n3. All Email Records:")
    manager.display_records()
    
    # Show records by threat level
    print("\n4. High Threat Emails:")
    high_threat = manager.get_records_by_threat_level('High')
    for record in high_threat:
        print(f"  - {record['fromEmail']}: {record['Subject']}")
    
    print("\n5. Critical Threat Emails:")
    critical_threat = manager.get_records_by_threat_level('Critical')
    for record in critical_threat:
        print(f"  - {record['fromEmail']}: {record['Subject']}")
    
    print(f"\nDemo completed! Check the '{manager.csv_filename}' file in your current directory.")


if __name__ == "__main__":
    main()

