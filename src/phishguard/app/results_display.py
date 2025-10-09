# Results Display Module - Simplified Pipeline Integration
import tkinter as tk
from typing import Dict, List, Any
from phishguard.schema import EmailRecord, RuleHit


class ResultsDisplayManager:
# ====================================================================
#                    Widgets Setup and Formatting                    =
# ====================================================================
    
    def __init__(self, results_text_widget, batch_results_text_widget):
        # Store GUI widgets for displaying results
        self.results_text = results_text_widget           # Individual email results
        self.batch_results_text = batch_results_text_widget  # Batch analysis results
        
        # Set up colors and formatting
        self._setup_text_formatting()
    
    def _setup_text_formatting(self):
        # color tags for different threat levels
        widgets = [self.results_text, self.batch_results_text]
        
        for widget in widgets:
            widget.tag_configure("safe", foreground="green", font=('Arial', 10, 'bold'))
            widget.tag_configure("suspicious", foreground="orange", font=('Arial', 10, 'bold'))
            widget.tag_configure("phishing", foreground="red", font=('Arial', 10, 'bold'))
            widget.tag_configure("header", foreground="black", font=('Arial', 12, 'bold'))
            widget.tag_configure("subheader", foreground="black", font=('Arial', 10, 'bold'))

# ====================================================================
#                    UI Entry Points (Setup UI to be displayed)      =
# ====================================================================

    def display_individual_results(self, email_record: EmailRecord, total_score: float, rule_hits: List[RuleHit], config: Dict[str, Any]):
        # Display results for ONE email analysis using pipeline data
        classification = self._determine_classification(total_score, config)
        
        # Render formatted data in GUI
        self._display_results_safely(self.results_text, lambda: [
            self._show_report_header(),
            self._show_email_details(email_record),
            self._show_security_verdict(classification, total_score),
            self._show_detailed_analysis(rule_hits),
            self._show_security_recommendations(classification)
        ])

    def display_batch_results(self, batch_results):
        # Display results for MULTIPLE email analysis
        self._display_results_safely(self.batch_results_text, lambda: [
            self._show_batch_header(),
            self._show_executive_summary(batch_results['summary']),
            self._show_individual_email_analysis(batch_results['results']),
            self._show_batch_recommendations(batch_results['summary'])
        ])

    def format_batch_analysis_results(self, email_record: EmailRecord, total_score: float, rule_hits: List[RuleHit], config: Dict[str, Any], email_number: int) -> Dict[str, Any]:
        # Format individual email for inclusion in batch display
        classification = self._determine_classification(total_score, config)
        
        return {
            'classification': classification,
            'final_score': total_score,
            'email_number': email_number,
            'email_data': {
                'sender': email_record.from_addr,
                'subject': email_record.subject,
                'body_length': len(email_record.body_text or '')
            },
            'rule_hits': rule_hits
        }

# ==============================================================================
#          Helper Functions                                                   =
# ==============================================================================

    def _determine_classification(self, total_score: float, config: Dict[str, Any]) -> str:
        # Convert score to threat level
        thresholds = config.get('thresholds', {})
        safe_max = thresholds.get('safe_max', 2.0)
        phishing_min = thresholds.get('phishing_min', 2.0)
        
        if total_score < safe_max:
            return "SAFE"
        elif total_score >= phishing_min:
            return "PHISHING"
        else:
            return "SUSPICIOUS"

    def _display_results_safely(self, widget, content_func):
        # STEP 1: Enable editing & clear old content
        widget.config(state=tk.NORMAL)
        widget.delete(1.0, tk.END)
        
        # STEP 2: Render the content 
        content_func()
        
        # STEP 3: Make read-only (prevents editing)
        widget.config(state=tk.DISABLED)

# ==============================================================================
#         CONTENT RENDERERS (Generate Display Sections)                      =
# ==============================================================================

    # INDIVIDUAL EMAIL CONTENT RENDERERS    
    def _show_report_header(self):
        # main report title
        self.results_text.insert(tk.END, "EMAIL ANALYSIS REPORT\n", "header")
        self.results_text.insert(tk.END, "=" * 50 + "\n\n")
    
    def _show_email_details(self, email_record: EmailRecord):
        # Render basic email information
        self.results_text.insert(tk.END, "Email Details:\n", "subheader")
        self.results_text.insert(tk.END, f"   From: {email_record.from_addr}\n")
        self.results_text.insert(tk.END, f"   Subject: {email_record.subject}\n")
        self.results_text.insert(tk.END, f"   Body Length: {len(email_record.body_text or '')} characters\n\n")
    
    def _show_security_verdict(self, classification: str, score: float):
        # main security classification
        self.results_text.insert(tk.END, "Security Assessment:\n", "subheader")
        self.results_text.insert(tk.END, "   Classification: ")
        
        # Color-coded classification
        if classification == "SAFE":
            self.results_text.insert(tk.END, f"{classification}\n", "safe")
            explanation = "This email appears to be legitimate and safe to interact with."
        elif classification == "SUSPICIOUS":
            self.results_text.insert(tk.END, f"{classification}\n", "suspicious")
            explanation = "This email has suspicious characteristics. Exercise caution."
        else:  # PHISHING
            self.results_text.insert(tk.END, f"{classification}\n", "phishing")
            explanation = "This email shows strong indicators of being a phishing attempt."
        
        self.results_text.insert(tk.END, f"   Risk Score: {score:.1f}\n")
        self.results_text.insert(tk.END, f"   Assessment: {explanation}\n\n")
    
    def _show_detailed_analysis(self, rule_hits: List[RuleHit]):
        # detailed breakdown of all security checks
        self.results_text.insert(tk.END, "Detailed Analysis:\n", "subheader")
        self.results_text.insert(tk.END, "-" * 30 + "\n\n")
        
        # Group rule hits by type
        failed_rules = [hit for hit in rule_hits if not hit.passed]
        passed_rules = [hit for hit in rule_hits if hit.passed]
        
        if failed_rules:
            self.results_text.insert(tk.END, "SECURITY CONCERNS DETECTED:\n")
            for rule in failed_rules:
                self.results_text.insert(tk.END, f"   - {rule.rule_name.replace('_', ' ').title()}: {rule.details.get('reason', 'Security issue detected')}\n")
                self.results_text.insert(tk.END, f"     Risk Points: {rule.score_delta}\n")
            self.results_text.insert(tk.END, "\n")
        
        if passed_rules:
            self.results_text.insert(tk.END, "SECURITY CHECKS PASSED:\n")
            for rule in passed_rules:
                self.results_text.insert(tk.END, f"   - {rule.rule_name.replace('_', ' ').title()}: {rule.details.get('reason', 'No issues detected')}\n")
            self.results_text.insert(tk.END, "\n")
    
    def _show_security_recommendations(self, classification: str):
        # Actionable security advice
        self.results_text.insert(tk.END, "Recommendations:\n", "subheader")
        self.results_text.insert(tk.END, "-" * 20 + "\n")
        
        if classification == "SAFE":
            self.results_text.insert(tk.END, "SAFE: This email appears safe to interact with.\n", "safe")
            self.results_text.insert(tk.END, "   - You can safely read and respond to this email\n")
        elif classification == "SUSPICIOUS":
            self.results_text.insert(tk.END, "CAUTION: Exercise caution with this email:\n", "suspicious")
            self.results_text.insert(tk.END, "   - Verify sender identity through alternative means\n")
            self.results_text.insert(tk.END, "   - Avoid clicking any links until verified\n")
        else:  # PHISHING
            self.results_text.insert(tk.END, "SECURITY ALERT - Likely phishing attempt:\n", "phishing")
            self.results_text.insert(tk.END, "   - DO NOT click any links in this email\n")
            self.results_text.insert(tk.END, "   - DO NOT provide any personal information\n")
            self.results_text.insert(tk.END, "   - Report this email to your IT security team\n")

    # BATCH EMAIL CONTENT RENDERERS
    def _show_batch_header(self):
        # batch analysis title
        self.batch_results_text.insert(tk.END, "BATCH ANALYSIS REPORT\n", "header")
        self.batch_results_text.insert(tk.END, "=" * 40 + "\n\n")

    def _show_executive_summary(self, summary):
        # high-level batch statistics
        self.batch_results_text.insert(tk.END, "Summary\n", "subheader")
        self.batch_results_text.insert(tk.END, "-" * 15 + "\n")
        self.batch_results_text.insert(tk.END, f"Total Emails: {summary['total_emails']}\n")
        
        # Color-coded statistics
        self.batch_results_text.insert(tk.END, f"Safe Emails: {summary['safe_count']} ({summary['safe_percentage']:.1f}%)\n", "safe")
        self.batch_results_text.insert(tk.END, f"Suspicious Emails: {summary['suspicious_count']} ({summary['suspicious_percentage']:.1f}%)\n", "suspicious")
        self.batch_results_text.insert(tk.END, f"Phishing Emails: {summary['phishing_count']} ({summary['phishing_percentage']:.1f}%)\n", "phishing")
        
        # Overall risk assessment
        if summary['phishing_percentage'] > 20:
            risk_level, risk_color = "HIGH RISK", "phishing"
        elif summary['suspicious_percentage'] + summary['phishing_percentage'] > 30:
            risk_level, risk_color = "MEDIUM RISK", "suspicious"
        else:
            risk_level, risk_color = "LOW RISK", "safe"
        
        self.batch_results_text.insert(tk.END, f"\nOverall Risk Level: ")
        self.batch_results_text.insert(tk.END, f"{risk_level}\n", risk_color)

    def _show_individual_email_analysis(self, results):
        # summary of individual email results
        self.batch_results_text.insert(tk.END, "\nIndividual Results\n", "subheader")
        self.batch_results_text.insert(tk.END, "-" * 20 + "\n")
        
        for result in results:
            classification = result['classification']
            color = "safe" if classification == "SAFE" else ("suspicious" if classification == "SUSPICIOUS" else "phishing")
            
            self.batch_results_text.insert(tk.END, f"\nEmail #{result['email_number']}: ")
            self.batch_results_text.insert(tk.END, f"{classification}", color)
            self.batch_results_text.insert(tk.END, f" (Score: {result['final_score']:.1f})\n")
            
            self.batch_results_text.insert(tk.END, f"  From: {result['email_data']['sender']}\n")
            subject = result['email_data']['subject']
            self.batch_results_text.insert(tk.END, f"  Subject: {subject[:60]}{'...' if len(subject) > 60 else ''}\n")

    def _show_batch_recommendations(self, summary):
        # actionable batch recommendations
        self.batch_results_text.insert(tk.END, f"\nRecommendations\n", "subheader")
        self.batch_results_text.insert(tk.END, "-" * 15 + "\n")
        
        if summary['phishing_count'] > 0:
            self.batch_results_text.insert(tk.END, "Immediate Actions:\n", "phishing")
            self.batch_results_text.insert(tk.END, "   - Review all phishing emails immediately\n")
            self.batch_results_text.insert(tk.END, "   - Implement additional security measures\n")
        
        if summary['suspicious_count'] > 0:
            self.batch_results_text.insert(tk.END, "Cautionary Measures:\n", "suspicious")
            self.batch_results_text.insert(tk.END, "   - Review suspicious emails with security team\n")
        
        self.batch_results_text.insert(tk.END, "Ongoing Security:\n")
        self.batch_results_text.insert(tk.END, "   - Conduct regular security awareness training\n")
        self.batch_results_text.insert(tk.END, "   - Implement email filtering and monitoring\n")