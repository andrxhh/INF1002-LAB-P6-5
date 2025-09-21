#!/usr/bin/env python3
"""
Test file for storage.py - Email Report CSV Manager
This file contains test examples to verify the storage.py functionality.
"""

import sys
import os

# Add the parent directory to the path so we can import storage.py
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from phishguard.storage.storage import EmailReportManager

def test_storage_functionality():
    """
    Test the EmailReportManager functionality with example emails.
    """
    print("=" * 60)
    print("TESTING STORAGE.PY - EMAIL REPORT MANAGER")
    print("=" * 60)
    
    # Create a test manager with a test CSV file
    test_manager = EmailReportManager("test_emailReport.csv")
    
    # Test email examples with different threat levels
    test_emails = [
        {
            'fromEmail': 'phishing@fake-bank.com',
            'Subject': 'URGENT: Your account will be closed in 24 hours!',
            'Body': 'Dear customer, we have detected suspicious activity on your account. Click here immediately to verify your identity or your account will be permanently closed. This is your final warning!',
            'threatLevel': 'Critical'
        },
        {
            'fromEmail': 'noreply@legitimate-bank.com',
            'Subject': 'Monthly Statement Available',
            'Body': 'Your monthly bank statement is now available for download. Please log in to your online banking portal to view your statement.',
            'threatLevel': 'Low'
        },
        {
            'fromEmail': 'support@suspicious-site.org',
            'Subject': 'Update your payment information',
            'Body': 'We need to update your payment information. Please provide your credit card details and social security number to continue using our services.',
            'threatLevel': 'High'
        },
        {
            'fromEmail': 'newsletter@tech-news.com',
            'Subject': 'Weekly Technology Newsletter',
            'Body': 'This week in technology: New AI developments, cybersecurity updates, and the latest in software engineering. Read more about these exciting topics.',
            'threatLevel': 'Low'
        },
        {
            'fromEmail': 'admin@questionable-service.net',
            'Subject': 'Your subscription is about to expire',
            'Body': 'Your premium subscription will expire soon. Click here to renew and avoid losing access to our premium features. Limited time offer!',
            'threatLevel': 'Medium'
        }
    ]
    
    print("\n1. Adding test email records...")
    success_count = 0
    for email in test_emails:
        if test_manager.add_email_record(
            email['fromEmail'],
            email['Subject'],
            email['Body'],
            email['threatLevel']
        ):
            success_count += 1
    
    print(f"Successfully added {success_count} out of {len(test_emails)} test records")
    
    print("\n2. Displaying statistics...")
    stats = test_manager.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n3. Testing threat level filtering...")
    
    # Test High threat emails
    high_threat = test_manager.get_records_by_threat_level('High')
    print(f"\nHigh Threat Emails ({len(high_threat)} found):")
    for record in high_threat:
        print(f"  - {record['fromEmail']}: {record['Subject']}")
    
    # Test Critical threat emails
    critical_threat = test_manager.get_records_by_threat_level('Critical')
    print(f"\nCritical Threat Emails ({len(critical_threat)} found):")
    for record in critical_threat:
        print(f"  - {record['fromEmail']}: {record['Subject']}")
    
    print("\n4. Displaying all test records...")
    test_manager.display_records(limit=3)  # Show only first 3 records
    
    print("\n5. Testing CSV file creation...")
    print(f"Test CSV file created: test_emailReport.csv")
    
    print("\n" + "=" * 60)
    print("TEST COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    print("Check the 'test_emailReport.csv' file to see the test data.")
    
    return True

def test_specific_email_scenarios():
    """
    Test specific email scenarios that might be encountered in real phishing detection.
    """
    print("\n" + "=" * 60)
    print("TESTING SPECIFIC EMAIL SCENARIOS")
    print("=" * 60)
    
    # Create another test manager for specific scenarios
    scenario_manager = EmailReportManager("scenario_test.csv")
    
    # Scenario 1: Obvious phishing attempt
    scenario_manager.add_email_record(
        "urgent@paypal-security.com",
        "ACCOUNT SUSPENDED - IMMEDIATE ACTION REQUIRED",
        "Your PayPal account has been suspended due to security concerns. Click the link below immediately to restore access. Failure to respond within 24 hours will result in permanent account closure.",
        "Critical"
    )
    
    # Scenario 2: Legitimate business email
    scenario_manager.add_email_record(
        "orders@amazon.com",
        "Your order has been delivered",
        "Hello! Your recent order #123-4567890 has been delivered to your address. Thank you for shopping with Amazon!",
        "Low"
    )
    
    # Scenario 3: Suspicious but not obvious
    scenario_manager.add_email_record(
        "noreply@microsoft-update.com",
        "Windows Security Update Required",
        "A critical security update is available for your Windows system. Download and install this update immediately to protect your computer from malware.",
        "Medium"
    )
    
    print("Added 3 scenario test emails:")
    print("  - Critical: PayPal phishing attempt")
    print("  - Low: Legitimate Amazon delivery notification")
    print("  - Medium: Suspicious Microsoft update email")
    
    # Display the scenario results
    print("\nScenario Test Results:")
    scenario_manager.display_records()
    
    return True

if __name__ == "__main__":
    try:
        # Run the main test
        test_storage_functionality()
        
        # Run scenario tests
        test_specific_email_scenarios()
        
        print("\n" + "=" * 60)
        print("ALL TESTS COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print("Files created:")
        print("  - test_emailReport.csv (main test data)")
        print("  - scenario_test.csv (scenario test data)")
        print("=" * 60)
        
    except Exception as e:
        print(f"\nERROR: Test failed with exception: {str(e)}")
        print("Make sure storage.py is in the correct location and accessible.")
        sys.exit(1)
