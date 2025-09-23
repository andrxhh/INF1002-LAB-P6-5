#!/usr/bin/env python3
#====================================
#     Results Display              =
#====================================

import tkinter as tk


class ResultsDisplayManager:
    """Manages the display of email analysis results in the GUI"""
    
    def __init__(self, results_text_widget, batch_results_text_widget):
        """
        Set up the results display manager
        
        Args:
            results_text_widget: Text area for individual email results
            batch_results_text_widget: Text area for batch analysis results
        """
        # Store references to the text widgets from the GUI
        self.results_text = results_text_widget           # Individual analysis
        self.batch_results_text = batch_results_text_widget  # Batch analysis
        
        # Set up color formatting 
        self._setup_text_tags()
    
    # ====================================
    #  Setup Functions                   =
    # ====================================
    
    def _setup_text_tags(self):
        """Configure text formatting tags for both widgets"""
        # Apply color and font settings to both text widgets
        widgets = [self.results_text, self.batch_results_text]
        
        # Configure color tags for threat levels
        for widget in widgets:
            widget.tag_configure("safe", foreground="green", font=('Arial', 12, 'bold'))      
            widget.tag_configure("suspicious", foreground="orange", font=('Arial', 12, 'bold'))
            widget.tag_configure("phishing", foreground="red", font=('Arial', 12, 'bold'))    
            widget.tag_configure("header", foreground="white", font=('Arial', 12, 'bold'))    #header
            widget.tag_configure("subheader", foreground="purple", font=('Arial', 12, 'bold'))  # subheader
    
    # ====================================
    # Individual Email Analysis Display  =
    # ====================================
    
    def display_individual_results(self, results, sender, subject, body):
        # Enable editing
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)  # Clear previous results
        
        # Extract the main analysis results
        classification = results['classification']  # SAFE, SUSPICIOUS, or PHISHING
        score = results['final_score']             # Numerical threat score
        
        # Main Header
        # Display the main report title in white
        self.results_text.insert(tk.END, "EMAIL SECURITY ANALYSIS REPORT\n", "header")
        self.results_text.insert(tk.END, "=" * 70 + "\n\n")  # divider line
        
        # Email Details
        # Show basic info about the email
        self.results_text.insert(tk.END, "Analyzed Email:\n", "subheader")
        self.results_text.insert(tk.END, f"   From: {sender}\n")
        self.results_text.insert(tk.END, f"   Subject: {subject}\n")
        self.results_text.insert(tk.END, f"   Body Length: {len(body)} characters\n\n")
        
        # Security Verdict
        # Display the main classification
        self.results_text.insert(tk.END, "SECURITY VERDICT:\n", "subheader")
        self.results_text.insert(tk.END, "   Classification: ")
        
        # Color code the classification
        if classification == "SAFE":
            self.results_text.insert(tk.END, f"{classification}\n", "safe")  # Green text
            verdict_explanation = "This email appears to be legitimate and safe to interact with."
        elif classification == "SUSPICIOUS":
            self.results_text.insert(tk.END, f"{classification}\n", "suspicious")  # Orange text
            verdict_explanation = "This email has suspicious characteristics. Exercise caution."
        else:  # PHISHING
            self.results_text.insert(tk.END, f"{classification}\n", "phishing")  # Red text
            verdict_explanation = "This email shows strong indicators of being a phishing attempt."
        
        # Show numerical risk score and explanation
        self.results_text.insert(tk.END, f"   Risk Score: {score}/50\n")
        self.results_text.insert(tk.END, f"   Assessment: {verdict_explanation}\n\n")
        # Detailed Analysis
        # Break down specific areas
        self.results_text.insert(tk.END, "DETAILED SECURITY ANALYSIS:\n", "subheader")
        self.results_text.insert(tk.END, "-" * 50 + "\n\n")
        
        # Display each analysis
        self._display_whitelist_analysis(results['whitelist'])    # Check if sender is trusted
        self._display_content_analysis(results['keywords'])       # Look for suspicious words
        self._display_spoofing_analysis(results['spoofing'])      # Check for impersonation
        self._display_url_analysis(results['urls'])               # Analyze links in email
        self._display_security_recommendations(classification)    # Give user advice
        
        # Disable editing
        self.results_text.config(state=tk.DISABLED)
    
    # Individual Analysis Helper Functions
    # =====================================
    
    def _display_whitelist_analysis(self, whitelist):
        """Display sender domain analysis - checks if sender is from a trusted domain"""
        # Show domain trust analysis
        self.results_text.insert(tk.END, "Sender Domain Analysis:\n")
        if whitelist['is_safe']:
            # Green text for trusted domains
            self.results_text.insert(tk.END, "   SAFE: Sender domain is in trusted whitelist\n", "safe")
        else:
            # Warning for unknown domains
            self.results_text.insert(tk.END, "   WARNING: Sender domain not in trusted whitelist\n")
        # Show how many risk points this added to the total score
        self.results_text.insert(tk.END, f"   Risk Points: {whitelist['score']}\n\n")
    
    def _display_content_analysis(self, keywords):
        # Check email content for red flags
        self.results_text.insert(tk.END, "Content Analysis:\n")
        if keywords['found']:
            # Warning text for emails with suspicious keywords
            self.results_text.insert(tk.END, f"   WARNING: Suspicious keywords detected:\n")
            # Show first suspicious keywords found (only show first 10)
            for keyword in keywords['found'][:10]:
                self.results_text.insert(tk.END, f"      • {keyword}\n")
            # If there are more than 10, say how many more
            if len(keywords['found']) > 10:
                self.results_text.insert(tk.END, f"      ... and {len(keywords['found']) - 10} more\n")
        else:
            # Green text for clean content
            self.results_text.insert(tk.END, "   SAFE: No suspicious keywords detected\n", "safe")
        # Show risk points
        self.results_text.insert(tk.END, f"   Risk Points: {keywords['score']}\n\n")
    
    def _display_spoofing_analysis(self, spoofing):
        """Display domain spoofing analysis - checks if sender is impersonating known companies"""
        # Look for fake domains that look like real companies (like "paypaI.com" instead of "paypal.com")
        self.results_text.insert(tk.END, "Domain Spoofing Analysis:\n")
        if spoofing['detected']:
            # Alert for potential impersonation attempts
            self.results_text.insert(tk.END, f"   ALERT: Potential domain spoofing detected\n")
            self.results_text.insert(tk.END, f"   Details: {spoofing['reason']}\n")
        else:
            # Green text for legitimate domains
            self.results_text.insert(tk.END, "   SAFE: No domain spoofing detected\n", "safe")
        # Show risk points
        self.results_text.insert(tk.END, f"   Risk Points: {spoofing['score']}\n\n")
    
    def _display_url_analysis(self, urls):
        """Display URL security analysis - checks all links in the email for red flags"""
        # Analyze any clickable links for suspicious characteristics
        self.results_text.insert(tk.END, "URL Security Analysis:\n")
        if urls['suspicious']:
            # Alert for dangerous links
            self.results_text.insert(tk.END, f"   ALERT: {len(urls['suspicious'])} suspicious URLs detected:\n")
            # Show first 5 problematic URLs (don't overwhelm user)
            for i, url in enumerate(urls['suspicious'][:5]):
                # Parse URL and reason if formatted as "url (reason)"
                if ' (' in url and url.endswith(')'):
                    url_part, reason_part = url.rsplit(' (', 1)
                    reason_part = reason_part[:-1]  # Remove closing parenthesis
                    self.results_text.insert(tk.END, f"      {i+1}. {url_part}\n")
                    self.results_text.insert(tk.END, f"         Issue: {reason_part}\n")
                else:
                    # Simple URL without detailed reason
                    self.results_text.insert(tk.END, f"      {i+1}. {url}\n")
            # If there are more than 5 bad URLs, say how many more
            if len(urls['suspicious']) > 5:
                self.results_text.insert(tk.END, f"      ... and {len(urls['suspicious']) - 5} more suspicious URLs\n")
        else:
            # Green text for emails with safe links
            self.results_text.insert(tk.END, "   SAFE: No suspicious URLs detected\n", "safe")
        # Show risk points
        self.results_text.insert(tk.END, f"   Risk Points: {urls['score']}\n\n")
    
    def _display_security_recommendations(self, classification):
        """Display security recommendations - gives user actionable advice based on threat level"""
        # Recommendations section
        self.results_text.insert(tk.END, "SECURITY RECOMMENDATIONS:\n", "subheader")
        self.results_text.insert(tk.END, "-" * 40 + "\n")
        
        if classification == "SAFE":
            self.results_text.insert(tk.END, "SAFE: This email appears safe to interact with.\n", "safe")
            self.results_text.insert(tk.END, "   • You can safely read and respond to this email\n")
            self.results_text.insert(tk.END, "   • Links and attachments appear legitimate\n")
            self.results_text.insert(tk.END, "   • Continue with normal email handling procedures\n")
        
        elif classification == "SUSPICIOUS":
            self.results_text.insert(tk.END, "CAUTION: Exercise caution with this email:\n", "suspicious")
            self.results_text.insert(tk.END, "   • Verify sender identity through alternative means\n")
            self.results_text.insert(tk.END, "   • Avoid clicking links or downloading attachments\n")
            self.results_text.insert(tk.END, "   • Check with sender directly if the email seems unusual\n")
            self.results_text.insert(tk.END, "   • Consider forwarding to IT security team for review\n")
        
        else:
            self.results_text.insert(tk.END, "SECURITY ALERT - Likely phishing attempt:\n", "phishing")
            self.results_text.insert(tk.END, "   • DO NOT click any links in this email\n")
            self.results_text.insert(tk.END, "   • DO NOT download or open any attachments\n")
            self.results_text.insert(tk.END, "   • DO NOT provide any personal information\n")
            self.results_text.insert(tk.END, "   • Report this email to your IT security team immediately\n")
            self.results_text.insert(tk.END, "   • Delete this email after reporting\n")
            self.results_text.insert(tk.END, "   • Alert colleagues about this phishing attempt\n")
    
    # ====================================
    # Batch Email Analysis Display      =
    # ====================================
    
    def display_batch_results(self, batch_results):
        # Enable editing
        self.batch_results_text.config(state=tk.NORMAL)
        self.batch_results_text.delete(1.0, tk.END)  # Clear previous results
        
        # Extract summary data
        summary = batch_results['summary']
        
        # Batch Report Header
        # Main title for the batch analysis
        self.batch_results_text.insert(tk.END, "BATCH EMAIL ANALYSIS REPORT\n", "header")
        self.batch_results_text.insert(tk.END, "=" * 70 + "\n\n")
        
        # Display different sections of the batch
        self._display_executive_summary(summary)                      # Overall statistics and overview
        self._display_individual_email_analysis(batch_results['results'])  # Details for each email
        self._display_batch_recommendations(summary)                  # Security advice for the batch
        
        # Disable editing
        self.batch_results_text.config(state=tk.DISABLED)
    
    # Batch Analysis Helper Functions
    # ================================
    
    def _display_executive_summary(self, summary):
        """Display executive summary for batch analysis - shows high-level statistics"""
        # Show overall statistics and key findings
        self.batch_results_text.insert(tk.END, "EXECUTIVE SUMMARY\n", "subheader")
        self.batch_results_text.insert(tk.END, "-" * 30 + "\n")
        self.batch_results_text.insert(tk.END, f"Total Emails Analyzed: {summary['total_emails']}\n")
        
        self.batch_results_text.insert(tk.END, f"Safe Emails: {summary['safe_count']} ({summary['safe_percentage']:.1f}%)\n", "safe")
        self.batch_results_text.insert(tk.END, f"Suspicious Emails: {summary['suspicious_count']} ({summary['suspicious_percentage']:.1f}%)\n", "suspicious")
        self.batch_results_text.insert(tk.END, f"Phishing Emails: {summary['phishing_count']} ({summary['phishing_percentage']:.1f}%)\n", "phishing")
        
        if summary['phishing_percentage'] > 20:
            risk_level = "HIGH RISK"
            risk_color = "phishing"
            risk_msg = "High volume of phishing emails detected! Immediate action required."
        elif summary['suspicious_percentage'] + summary['phishing_percentage'] > 30:
            risk_level = "MEDIUM RISK"
            risk_color = "suspicious"
            risk_msg = "Elevated suspicious email activity detected."
        else:
            risk_level = "LOW RISK"
            risk_color = "safe"
            risk_msg = "Email security within acceptable limits."
        
        self.batch_results_text.insert(tk.END, f"\nOverall Risk Level: ")
        self.batch_results_text.insert(tk.END, f"{risk_level}\n", risk_color)
        self.batch_results_text.insert(tk.END, f"Assessment: {risk_msg}\n\n")
    
    def _display_individual_email_analysis(self, results):
        """Display individual email results in batch analysis - shows details for each email"""
        # List out each email analyzed with its threat classification
        self.batch_results_text.insert(tk.END, "INDIVIDUAL EMAIL ANALYSIS\n", "subheader")
        self.batch_results_text.insert(tk.END, "-" * 40 + "\n")
        
        # Loop through each email
        for result in results:
            classification = result['classification']  # SAFE, SUSPICIOUS, or PHISHING
            
            # Choose color based on threat level
            if classification == "SAFE":
                color = "safe"         # Green for safe emails
            elif classification == "SUSPICIOUS":
                color = "suspicious"   # Orange for suspicious emails
            else:  # PHISHING
                color = "phishing"     # Red for phishing emails
            
            # Display email number, classification, and risk score
            self.batch_results_text.insert(tk.END, f"\nEmail #{result['email_number']}: ")
            self.batch_results_text.insert(tk.END, f"{classification}", color)  # Color-coded classification
            self.batch_results_text.insert(tk.END, f" (Risk Score: {result['final_score']}/50)\n")
            
            self.batch_results_text.insert(tk.END, f"  From: {result['email_data']['sender']}\n")
            self.batch_results_text.insert(tk.END, f"  Subject: {result['email_data']['subject'][:60]}{'...' if len(result['email_data']['subject']) > 60 else ''}\n")
            
            if result['keywords']['found']:
                keywords = result['keywords']['found'][:3]
                self.batch_results_text.insert(tk.END, f"  Key Issues: {', '.join(keywords)}")
                if len(result['keywords']['found']) > 3:
                    self.batch_results_text.insert(tk.END, f" +{len(result['keywords']['found']) - 3} more")
                self.batch_results_text.insert(tk.END, "\n")
            
            if result['urls']['suspicious']:
                self.batch_results_text.insert(tk.END, f"  Suspicious URLs: {len(result['urls']['suspicious'])} detected\n")
    
    def _display_batch_recommendations(self, summary):
        """Display recommendations for batch analysis"""
        self.batch_results_text.insert(tk.END, f"\nRECOMMENDATIONS\n", "subheader")
        self.batch_results_text.insert(tk.END, "-" * 25 + "\n")
        
        if summary['phishing_count'] > 0:
            self.batch_results_text.insert(tk.END, "IMMEDIATE ACTIONS:\n", "phishing")
            self.batch_results_text.insert(tk.END, "   • Review all PHISHING emails immediately\n")
            self.batch_results_text.insert(tk.END, "   • Block sender domains from confirmed phishing emails\n")
            self.batch_results_text.insert(tk.END, "   • Notify affected users about phishing attempts\n")
            self.batch_results_text.insert(tk.END, "   • Update email security policies\n\n")
        
        if summary['suspicious_count'] > 0:
            self.batch_results_text.insert(tk.END, "PREVENTIVE MEASURES:\n", "suspicious")
            self.batch_results_text.insert(tk.END, "   • Review suspicious emails for false positives\n")
            self.batch_results_text.insert(tk.END, "   • Implement additional verification procedures\n")
            self.batch_results_text.insert(tk.END, "   • Consider enhanced monitoring for flagged senders\n\n")
        
        self.batch_results_text.insert(tk.END, "ONGOING SECURITY:\n")
        self.batch_results_text.insert(tk.END, "   • Conduct regular security awareness training\n")
        self.batch_results_text.insert(tk.END, "   • Update threat intelligence databases regularly\n")
        self.batch_results_text.insert(tk.END, "   • Monitor email security metrics weekly\n")
        self.batch_results_text.insert(tk.END, "   • Review and test incident response procedures\n")
