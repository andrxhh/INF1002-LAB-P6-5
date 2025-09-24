# Results Display Module
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
            widget.tag_configure("safe", foreground="green", font=('Arial', 12, 'bold'))
            widget.tag_configure("suspicious", foreground="orange", font=('Arial', 12, 'bold'))
            widget.tag_configure("phishing", foreground="red", font=('Arial', 12, 'bold'))
            widget.tag_configure("header", foreground="white", font=('Arial', 12, 'bold'))
            widget.tag_configure("subheader", foreground="purple", font=('Arial', 12, 'bold'))


# ====================================================================
#                    UI Entry Points (Setup UI to be displayed)      =
# ====================================================================

    def display_individual_results(self, email_record: EmailRecord, total_score: float, rule_hits: List[RuleHit], config: Dict[str, Any]):
        # Display results for ONE email analysis
        # Transform raw data into display-ready format
        display_data = self._format_email_for_display(email_record, total_score, rule_hits, config)
        
        # Render formatted data in GUI
        self._display_results_safely(self.results_text, lambda: [
            self._show_report_header(),
            self._show_email_details(email_record),
            self._show_security_verdict(display_data),
            self._show_detailed_analysis(display_data),
            self._show_security_recommendations(display_data['classification'])
        ])

    def display_batch_results(self, batch_results):
        # Display results for MULTIPLE email analysis
        # Render batch data in GUI
        self._display_results_safely(self.batch_results_text, lambda: [
            self._show_batch_header(),
            self._show_executive_summary(batch_results['summary']),
            self._show_individual_email_analysis(batch_results['results']),
            self._show_batch_recommendations(batch_results['summary'])
        ])

    def format_batch_analysis_results(self, email_record: EmailRecord, total_score: float, rule_hits: List[RuleHit], config: Dict[str, Any], email_number: int) -> Dict[str, Any]:
        # Format individual email for inclusion in batch display
        display_data = self._format_email_for_display(email_record, total_score, rule_hits, config)
        
        # Add batch-specific metadata
        display_data['email_number'] = email_number
        display_data['email_data'] = {
            'sender': email_record.from_addr,
            'subject': email_record.subject,
            'body_length': len(email_record.body_text or '')
        }
        return display_data


# ==============================================================================
#          Transform raw data into display-ready format                       =
# ==============================================================================

    def _format_email_for_display(self, email_record: EmailRecord, total_score: float, rule_hits: List[RuleHit], config: Dict[str, Any]) -> Dict[str, Any]:
        # Determine overall threat classification
        classification = self._determine_classification(total_score, config)
        
        # Organize rule results by security category
        rule_results = self._extract_rule_results(rule_hits, email_record, config)
        
        # Package everything into clean display format
        return {
            'classification': classification,       # "SAFE", "SUSPICIOUS", or "PHISHING"
            'final_score': total_score,            # Numerical risk score
            'whitelist': rule_results['whitelist'], # Domain trust analysis
            'keywords': rule_results['keywords'],   # Suspicious content analysis   
            'spoofing': rule_results['spoofing'],   # Domain impersonation analysis
            'urls': rule_results['urls'],           # Link security analysis
            'rule_hits': rule_hits,                # Raw data for advanced users
            'max_score': 50                        # Maximum possible score
        }
    
    def _determine_classification(self, total_score: float, config: Dict[str, Any]) -> str:
        # Convert score to threat level
        thresholds = config.get('thresholds', {})
        safe_max = thresholds.get('safe_max', 2.0)
        phishing_min = thresholds.get('phishing_min', 2.0)
        
        if total_score <= safe_max:
            return "SAFE"
        elif total_score >= phishing_min:
            return "PHISHING"
        else:
            return "SUSPICIOUS"
    
    def _extract_rule_results(self, rule_hits: List[RuleHit], email_record: EmailRecord, config: Dict[str, Any]) -> Dict[str, Any]:
        # Find specific rule results
        whitelist_hit = next((hit for hit in rule_hits if hit.rule_name == 'whitelist'), None)
        keywords_hit = next((hit for hit in rule_hits if hit.rule_name == 'keywords'), None)
        urls_hit = next((hit for hit in rule_hits if hit.rule_name == 'url_redflags'), None)
        lookalike_hit = next((hit for hit in rule_hits if hit.rule_name == 'lookalike_domain'), None)
        
        return {
            'whitelist': self._format_whitelist_results(whitelist_hit),
            'keywords': self._format_keywords_results(keywords_hit, config),
            'spoofing': self._format_spoofing_results(lookalike_hit),
            'urls': self._format_url_results(urls_hit, email_record)
        }
    
    # Convert raw rule data to display format
    def _format_whitelist_results(self, whitelist_hit) -> Dict[str, Any]:
        return {
            'is_safe': whitelist_hit.passed if whitelist_hit else False,
            'score': abs(whitelist_hit.score_delta) if whitelist_hit else 0.0
        }
    
    def _format_keywords_results(self, keywords_hit, config) -> Dict[str, Any]:
        keywords_found = []
        if keywords_hit and not keywords_hit.passed:
            keywords_found = list(config.get('rules', {}).get('keywords', {}).get('weights', {}).keys())[:5]
        
        return {
            'found': keywords_found,
            'score': keywords_hit.score_delta if keywords_hit else 0.0
        }
    
    def _format_spoofing_results(self, lookalike_hit) -> Dict[str, Any]:
        return {
            'detected': lookalike_hit and not lookalike_hit.passed,
            'reason': lookalike_hit.details.get('reason', 'Domain similarity detected') if lookalike_hit and not lookalike_hit.passed else '',
            'score': lookalike_hit.score_delta if lookalike_hit else 0.0
        }
    
    def _format_url_results(self, urls_hit, email_record) -> Dict[str, Any]:
        suspicious_urls = []
        if urls_hit and not urls_hit.passed:
            for url in email_record.urls:
                suspicious_urls.append(f"{url} (suspicious patterns detected)")
        
        return {
            'suspicious': suspicious_urls,
            'score': urls_hit.score_delta if urls_hit else 0.0
        }


# ==============================================================================
#              GUI Setup (for batch & Individual)                             =
# ==============================================================================

    def _display_results_safely(self, widget, content_func):
        # STEP 1: Enable editing & clear old content
        widget.config(state=tk.NORMAL)
        widget.delete(1.0, tk.END)
        
        # STEP 2: Render the content 
        content_func()
        
        # STEP 3: Make read-only (prevents editing)
        widget.config(state=tk.DISABLED)


# ==============================================================================
#         SECTION 4: CONTENT RENDERERS (Generate Display Sections)
# ==============================================================================

    # INDIVIDUAL EMAIL CONTENT RENDERERS    
    def _show_report_header(self):
        # main report title
        self.results_text.insert(tk.END, "EMAIL SECURITY ANALYSIS REPORT\n", "header")
        self.results_text.insert(tk.END, "=" * 70 + "\n\n")
    
    def _show_email_details(self, email_record: EmailRecord):
        # Render basic email information
        self.results_text.insert(tk.END, "Analyzed Email:\n", "subheader")
        self.results_text.insert(tk.END, f"   From: {email_record.from_addr}\n")
        self.results_text.insert(tk.END, f"   Subject: {email_record.subject}\n")
        self.results_text.insert(tk.END, f"   Body Length: {len(email_record.body_text or '')} characters\n\n")
    
    def _show_security_verdict(self, display_data):
        # main security classification
        classification = display_data['classification']
        score = display_data['final_score']
        
        self.results_text.insert(tk.END, "SECURITY VERDICT:\n", "subheader")
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
        
        self.results_text.insert(tk.END, f"   Risk Score: {score}/50\n")
        self.results_text.insert(tk.END, f"   Assessment: {explanation}\n\n")
    
    def _show_detailed_analysis(self, display_data):
        # detailed breakdown of all security checks
        self.results_text.insert(tk.END, "DETAILED SECURITY ANALYSIS:\n", "subheader")
        self.results_text.insert(tk.END, "-" * 50 + "\n\n")
        
        # analysis section
        self._render_whitelist_analysis(display_data['whitelist'])
        self._render_content_analysis(display_data['keywords'])
        self._render_spoofing_analysis(display_data['spoofing'])
        self._render_url_analysis(display_data['urls'])
    
    def _render_whitelist_analysis(self, whitelist):
        # Render sender domain trust analysis
        self.results_text.insert(tk.END, "Sender Domain Analysis:\n")
        if whitelist['is_safe']:
            self.results_text.insert(tk.END, "   SAFE: Sender domain is in trusted whitelist\n", "safe")
        else:
            self.results_text.insert(tk.END, "   WARNING: Sender domain not in trusted whitelist\n")
        self.results_text.insert(tk.END, f"   Risk Points: {whitelist['score']}\n\n")
    
    def _render_content_analysis(self, keywords):
        # Render email content analysis
        self.results_text.insert(tk.END, "Content Analysis:\n")
        if keywords['found']:
            self.results_text.insert(tk.END, f"   WARNING: Suspicious keywords detected:\n")
            for keyword in keywords['found'][:10]:
                self.results_text.insert(tk.END, f"      • {keyword}\n")
        else:
            self.results_text.insert(tk.END, "   SAFE: No suspicious keywords detected\n", "safe")
        self.results_text.insert(tk.END, f"   Risk Points: {keywords['score']}\n\n")
    
    def _render_spoofing_analysis(self, spoofing):
        # Spoofing analysis
        self.results_text.insert(tk.END, "Domain Spoofing Analysis:\n")
        if spoofing['detected']:
            self.results_text.insert(tk.END, f"   ALERT: Potential domain spoofing detected\n")
            self.results_text.insert(tk.END, f"   Details: {spoofing['reason']}\n")
        else:
            self.results_text.insert(tk.END, "   SAFE: No domain spoofing detected\n", "safe")
        self.results_text.insert(tk.END, f"   Risk Points: {spoofing['score']}\n\n")
    
    def _render_url_analysis(self, urls):
        # URL security analysis
        self.results_text.insert(tk.END, "URL Security Analysis:\n")
        if urls['suspicious']:
            self.results_text.insert(tk.END, f"   ALERT: {len(urls['suspicious'])} suspicious URLs detected:\n")
            for i, url in enumerate(urls['suspicious'][:5]):
                self.results_text.insert(tk.END, f"      {i+1}. {url}\n")
        else:
            self.results_text.insert(tk.END, "   SAFE: No suspicious URLs detected\n", "safe")
        self.results_text.insert(tk.END, f"   Risk Points: {urls['score']}\n\n")
    
    def _show_security_recommendations(self, classification):
        # Actionable security advice
        self.results_text.insert(tk.END, "SECURITY RECOMMENDATIONS:\n", "subheader")
        self.results_text.insert(tk.END, "-" * 40 + "\n")
        
        if classification == "SAFE":
            self.results_text.insert(tk.END, "SAFE: This email appears safe to interact with.\n", "safe")
            self.results_text.insert(tk.END, "   • You can safely read and respond to this email\n")
        elif classification == "SUSPICIOUS":
            self.results_text.insert(tk.END, "CAUTION: Exercise caution with this email:\n", "suspicious")
            self.results_text.insert(tk.END, "   • Verify sender identity through alternative means\n")
        else:  # PHISHING
            self.results_text.insert(tk.END, "SECURITY ALERT - Likely phishing attempt:\n", "phishing")
            self.results_text.insert(tk.END, "   • DO NOT click any links in this email\n")

    # BATCH EMAIL CONTENT RENDERERS
    def _show_batch_header(self):
        # batch analysis title
        self.batch_results_text.insert(tk.END, "BATCH EMAIL ANALYSIS REPORT\n", "header")
        self.batch_results_text.insert(tk.END, "=" * 70 + "\n\n")

    def _show_executive_summary(self, summary):
        # high-level batch statistics
        self.batch_results_text.insert(tk.END, "EXECUTIVE SUMMARY\n", "subheader")
        self.batch_results_text.insert(tk.END, "-" * 30 + "\n")
        self.batch_results_text.insert(tk.END, f"Total Emails Analyzed: {summary['total_emails']}\n")
        
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
        self.batch_results_text.insert(tk.END, "\nINDIVIDUAL EMAIL ANALYSIS\n", "subheader")
        self.batch_results_text.insert(tk.END, "-" * 40 + "\n")
        
        for result in results:
            classification = result['classification']
            color = "safe" if classification == "SAFE" else ("suspicious" if classification == "SUSPICIOUS" else "phishing")
            
            self.batch_results_text.insert(tk.END, f"\nEmail #{result['email_number']}: ")
            self.batch_results_text.insert(tk.END, f"{classification}", color)
            self.batch_results_text.insert(tk.END, f" (Risk Score: {result['final_score']}/50)\n")
            
            self.batch_results_text.insert(tk.END, f"  From: {result['email_data']['sender']}\n")
            subject = result['email_data']['subject']
            self.batch_results_text.insert(tk.END, f"  Subject: {subject[:60]}{'...' if len(subject) > 60 else ''}\n")

    def _show_batch_recommendations(self, summary):
        # actionable batch recommendations
        self.batch_results_text.insert(tk.END, f"\nRECOMMENDATIONS\n", "subheader")
        self.batch_results_text.insert(tk.END, "-" * 25 + "\n")
        
        if summary['phishing_count'] > 0:
            self.batch_results_text.insert(tk.END, "IMMEDIATE ACTIONS:\n", "phishing")
            self.batch_results_text.insert(tk.END, "   • Review all PHISHING emails immediately\n")
        
        self.batch_results_text.insert(tk.END, "ONGOING SECURITY:\n")
        self.batch_results_text.insert(tk.END, "   • Conduct regular security awareness training\n")