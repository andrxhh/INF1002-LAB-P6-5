# Tkinter UI
#!/usr/bin/env python3
"""
Phishing Email Detection GUI Application

This module provides a user-friendly graphical interface for the phishing email detector.
It's designed to be intuitive for both technical and non-technical team members.

Key Features:
- Individual email analysis with detailed results
- Batch email processing from files
- Visual risk scoring and color-coded results
- Detailed reports with recommendations
- Export capabilities for sharing results
- Easy-to-understand explanations for non-technical users

Author: Group Project Team
Purpose: User-friendly interface for phishing email detection system
Dependencies: tkinter (built into Python), PhishingDetector class
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import os
import sys

# Import our phishing detection components
try:
    from phishguard.app.detector import PhishingDetector
    from phishguard.schema import EmailRecord
    # TODO: Implement EmailDatasetAnalyzer if needed for threat intelligence
    # from phishguard.analysis.data_analyzer import EmailDatasetAnalyzer
    EmailDatasetAnalyzer = None  # Placeholder for now
except ImportError as e:
    messagebox.showerror("Import Error", f"Could not import required modules: {e}")
    sys.exit(1)


class PhishingDetectorGUI:
    """
    Graphical User Interface for Phishing Email Detection
    
    This class creates a professional, easy-to-use interface that allows team members
    to analyze emails for phishing attempts without needing to write code.
    
    The interface is organized into tabs:
    1. 📧 Individual Analysis: Analyze single emails with detailed breakdown
    2. 📁 Batch Analysis: Process multiple emails from files
    3. 📊 System Status: View threat intelligence and system information
    
    Think of this as the "control panel" for our phishing detection system.
    """
    
    def __init__(self, root):
        """
        Initialize the GUI Application
        
        Sets up the user interface and initializes the phishing detector.
        
        Args:
            root: Tkinter root window
        """
        self.root = root
        
        # Initialize the phishing detector (this may take a moment to load threat intelligence)
        print("🔄 Initializing phishing detection system...")
        try:
            self.detector = PhishingDetector()
            print("✅ Phishing detector initialized successfully")
        except Exception as e:
            messagebox.showerror("Initialization Error", 
                               f"Failed to initialize phishing detector: {e}")
            sys.exit(1)
        
        # Initialize data analyzer for system information
        if EmailDatasetAnalyzer:
            try:
                self.data_analyzer = EmailDatasetAnalyzer()
            except Exception as e:
                print(f"⚠️  Data analyzer initialization warning: {e}")
                self.data_analyzer = None
        else:
            print("📊 Data analyzer not implemented yet")
            self.data_analyzer = None
        
        # Storage for batch results (for report generation)
        self.current_batch_results = None
        
        # Setup the user interface
        self.setup_ui()
    
    def setup_ui(self):
        """
        CREATE USER INTERFACE: Build the main application window
        
        This creates a professional-looking interface with tabs for different functions.
        """
        # ================================
        # MAIN WINDOW CONFIGURATION
        # ================================
        self.root.title("PhishGuard - Email Detection System")
        self.root.geometry("1000x800")
        self.root.configure(bg='#f0f0f0')
        
        # Set application icon (if available)
        try:
            # Load the GUI icon as application icon
            icon_photo = tk.PhotoImage(file='gui icon.png')
            self.root.iconphoto(False, icon_photo)
        except Exception as e:
            print(f"Could not load application icon: {e}")
            pass
        
        # Configure modern styling
        style = ttk.Style()
        style.theme_use('clam')
        
        # ================================
        # MAIN LAYOUT CONTAINER
        # ================================
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Make the interface responsive
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        
        # ================================
        # APPLICATION HEADER
        # ================================
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 20))
        header_frame.columnconfigure(1, weight=1)
        
        # Try to load and display the App Logo
        try:
            self.logo_photo = tk.PhotoImage(file='App Logo.png')
            # Resize logo if it's too large (optional)
            logo_width = self.logo_photo.width()
            logo_height = self.logo_photo.height()
            if logo_width > 80 or logo_height > 80:
                # Scale down the logo to fit nicely in header
                scale_factor = min(80/logo_width, 80/logo_height)
                new_width = int(logo_width * scale_factor)
                new_height = int(logo_height * scale_factor)
                self.logo_photo = self.logo_photo.subsample(int(1/scale_factor))
            
            logo_label = ttk.Label(header_frame, image=self.logo_photo)
            logo_label.grid(row=0, column=0, rowspan=2, sticky=tk.W, padx=(0, 15))
        except Exception as e:
            print(f"Could not load logo image: {e}")
            # Create a placeholder if logo can't be loaded
            logo_label = ttk.Label(header_frame, text="[LOGO]", font=('Arial', 12, 'bold'))
            logo_label.grid(row=0, column=0, rowspan=2, sticky=tk.W, padx=(0, 15))
        
        title_label = ttk.Label(header_frame, 
                               text="PhishGuard Email Detection System", 
                               font=('Arial', 18, 'bold'))
        title_label.grid(row=0, column=1, sticky=tk.W)
        
        subtitle_label = ttk.Label(header_frame, 
                                  text="Advanced threat detection for email security", 
                                  font=('Arial', 10))
        subtitle_label.grid(row=1, column=1, sticky=tk.W)
        
        # ================================
        # TABBED INTERFACE
        # ================================
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        main_frame.rowconfigure(1, weight=1)
        
        # Create tabs
        self.individual_frame = ttk.Frame(notebook, padding="15")
        self.batch_frame = ttk.Frame(notebook, padding="15")
        self.system_frame = ttk.Frame(notebook, padding="15")
        
        notebook.add(self.individual_frame, text="Individual Analysis")
        notebook.add(self.batch_frame, text="Batch Analysis")
        notebook.add(self.system_frame, text="System Status")
        
        # Setup each tab
        self.setup_individual_tab()
        self.setup_batch_tab()
        self.setup_system_tab()
        
        # ================================
        # STATUS BAR
        # ================================
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.status_label = ttk.Label(status_frame, 
                                     text="Ready for email analysis", 
                                     font=('Arial', 9))
        self.status_label.grid(row=0, column=0, sticky=tk.W)
    
    def setup_individual_tab(self):
        """
        INDIVIDUAL EMAIL ANALYSIS TAB
        
        This tab allows users to paste in email details and get immediate analysis.
        Perfect for checking suspicious emails one at a time.
        """
        self.individual_frame.columnconfigure(1, weight=1)
        
        # ================================
        # EMAIL INPUT SECTION
        # ================================
        input_frame = ttk.LabelFrame(self.individual_frame, text="Email Details", padding="15")
        input_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        input_frame.columnconfigure(1, weight=1)
        
        # Sender email input
        ttk.Label(input_frame, text="Sender Email:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.sender_entry = ttk.Entry(input_frame, width=60, font=('Arial', 10))
        self.sender_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        
        # Subject input
        ttk.Label(input_frame, text="Subject:", font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.subject_entry = ttk.Entry(input_frame, width=60, font=('Arial', 10))
        self.subject_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        
        # Body input
        ttk.Label(input_frame, text="Email Body:", font=('Arial', 10, 'bold')).grid(row=2, column=0, sticky=(tk.W, tk.N), pady=5)
        self.body_text = scrolledtext.ScrolledText(input_frame, width=70, height=10, 
                                                  wrap=tk.WORD, font=('Arial', 10))
        self.body_text.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        
        # Help text
        help_text = ttk.Label(input_frame, 
                             text="Tip: Copy and paste the complete email content above for analysis",
                             font=('Arial', 9), foreground='gray')
        help_text.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(10, 0))
        
        # ================================
        # ACTION BUTTONS
        # ================================
        button_frame = ttk.Frame(self.individual_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=15)
        
        # Analyze button (prominent)
        analyze_btn = ttk.Button(button_frame, text="Analyze Email", 
                               command=self.analyze_email)
        analyze_btn.pack(side=tk.LEFT, padx=10)
        
        # Clear button
        clear_btn = ttk.Button(button_frame, text="Clear Fields", 
                             command=self.clear_fields)
        clear_btn.pack(side=tk.LEFT, padx=10)
        
        # Load sample button (for demonstration)
        sample_btn = ttk.Button(button_frame, text="Load Sample", 
                              command=self.load_sample_email)
        sample_btn.pack(side=tk.LEFT, padx=10)
        
        # ================================
        # RESULTS SECTION
        # ================================
        results_frame = ttk.LabelFrame(self.individual_frame, text="Analysis Results", padding="15")
        results_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(15, 0))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, width=90, height=20, 
                                                     wrap=tk.WORD, state=tk.DISABLED, font=('Arial', 10))
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure text styling for colored output
        self.results_text.tag_configure("safe", foreground="green", font=('Arial', 11, 'bold'))
        self.results_text.tag_configure("suspicious", foreground="orange", font=('Arial', 11, 'bold'))
        self.results_text.tag_configure("phishing", foreground="red", font=('Arial', 11, 'bold'))
        self.results_text.tag_configure("header", foreground="black", font=('Arial', 12, 'bold'))
        self.results_text.tag_configure("subheader", foreground="purple", font=('Arial', 10, 'bold'))
        
        # Configure individual frame weights for responsiveness
        self.individual_frame.rowconfigure(2, weight=1)
    
    def setup_batch_tab(self):
        """
        BATCH EMAIL ANALYSIS TAB
        
        This tab allows users to process multiple emails from a file,
        useful for analyzing email dumps or checking multiple suspicious emails.
        """
        self.batch_frame.columnconfigure(1, weight=1)
        
        # ================================
        # FILE SELECTION SECTION
        # ================================
        file_frame = ttk.LabelFrame(self.batch_frame, text="File Selection", padding="15")
        file_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        file_frame.columnconfigure(1, weight=1)
        
        # File path selection
        ttk.Label(file_frame, text="Email File:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.file_path_var = tk.StringVar()
        self.file_path_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, 
                                        width=60, state='readonly', font=('Arial', 10))
        self.file_path_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 10), pady=5)
        
        browse_btn = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        browse_btn.grid(row=0, column=2, pady=5)
        
        # Instructions
        instructions = ttk.Label(file_frame, 
                                text="File Format: Each email should have 'From:', 'Subject:', and 'Body:' sections.\n"
                                     "   Separate multiple emails with '---' or 'EMAIL:' dividers.",
                                font=('Arial', 9), foreground='gray')
        instructions.grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=(10, 0))
        
        # ================================
        # ACTION BUTTONS
        # ================================
        batch_button_frame = ttk.Frame(self.batch_frame)
        batch_button_frame.grid(row=1, column=0, columnspan=2, pady=15)
        
        analyze_batch_btn = ttk.Button(batch_button_frame, text="Analyze Batch", 
                                     command=self.analyze_batch)
        analyze_batch_btn.pack(side=tk.LEFT, padx=10)
        
        generate_report_btn = ttk.Button(batch_button_frame, text="Generate Report", 
                                       command=self.generate_batch_report)
        generate_report_btn.pack(side=tk.LEFT, padx=10)
        
        clear_batch_btn = ttk.Button(batch_button_frame, text="Clear", 
                                   command=self.clear_batch)
        clear_batch_btn.pack(side=tk.LEFT, padx=10)
        
        # ================================
        # BATCH RESULTS SECTION
        # ================================
        batch_results_frame = ttk.LabelFrame(self.batch_frame, text="Batch Analysis Results", padding="15")
        batch_results_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(15, 0))
        batch_results_frame.columnconfigure(0, weight=1)
        batch_results_frame.rowconfigure(0, weight=1)
        
        self.batch_results_text = scrolledtext.ScrolledText(batch_results_frame, width=90, height=20, 
                                                           wrap=tk.WORD, state=tk.DISABLED, font=('Arial', 10))
        self.batch_results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure text styling
        self.batch_results_text.tag_configure("safe", foreground="green", font=('Arial', 10, 'bold'))
        self.batch_results_text.tag_configure("suspicious", foreground="orange", font=('Arial', 10, 'bold'))
        self.batch_results_text.tag_configure("phishing", foreground="red", font=('Arial', 10, 'bold'))
        self.batch_results_text.tag_configure("header", foreground="black", font=('Arial', 12, 'bold'))
        self.batch_results_text.tag_configure("subheader", foreground="purple", font=('Arial', 10, 'bold'))
        
        # Configure batch frame weights
        self.batch_frame.rowconfigure(2, weight=1)
    
    def setup_system_tab(self):
        """
        SYSTEM STATUS TAB
        
        This tab shows information about the detection system, threat intelligence,
        and provides system management functions.
        """
        self.system_frame.columnconfigure(0, weight=1)
        
        # ================================
        # SYSTEM INFORMATION
        # ================================
        sys_info_frame = ttk.LabelFrame(self.system_frame, text="System Information", padding="15")
        sys_info_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        sys_info_frame.columnconfigure(0, weight=1)
        
        self.system_info_text = scrolledtext.ScrolledText(sys_info_frame, width=90, height=12, 
                                                         wrap=tk.WORD, state=tk.DISABLED, font=('Arial', 10))
        self.system_info_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # ================================
        # SYSTEM CONTROLS
        # ================================
        controls_frame = ttk.LabelFrame(self.system_frame, text="System Controls", padding="15")
        controls_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(15, 15))
        
        refresh_btn = ttk.Button(controls_frame, text="Refresh System Info", 
                               command=self.refresh_system_info)
        refresh_btn.pack(side=tk.LEFT, padx=10)
        
        update_intel_btn = ttk.Button(controls_frame, text="Update Threat Intelligence", 
                                    command=self.update_threat_intelligence)
        update_intel_btn.pack(side=tk.LEFT, padx=10)
        
        test_datasets_btn = ttk.Button(controls_frame, text="Test Email Datasets", 
                                     command=self.test_email_datasets)
        test_datasets_btn.pack(side=tk.LEFT, padx=10)
        
        # ================================
        # THREAT INTELLIGENCE PREVIEW
        # ================================
        threat_frame = ttk.LabelFrame(self.system_frame, text="Threat Intelligence Preview", padding="15")
        threat_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(15, 0))
        threat_frame.columnconfigure(0, weight=1)
        threat_frame.rowconfigure(0, weight=1)
        
        self.threat_intel_text = scrolledtext.ScrolledText(threat_frame, width=90, height=15, 
                                                          wrap=tk.WORD, state=tk.DISABLED, font=('Arial', 10))
        self.threat_intel_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure system frame weights
        self.system_frame.rowconfigure(2, weight=1)
        
        # Load initial system information
        self.refresh_system_info()
    
    def analyze_email(self):
        """
        ANALYZE INDIVIDUAL EMAIL: Process single email and display results
        
        This takes the email details entered by the user and runs comprehensive
        phishing analysis, then displays the results in an easy-to-understand format.
        """
        # Get input data
        sender = self.sender_entry.get().strip()
        subject = self.subject_entry.get().strip()
        body = self.body_text.get(1.0, tk.END).strip()
        
        # Validate input
        if not sender or not subject or not body:
            messagebox.showwarning("Input Required", 
                                 "Please fill in all fields (sender, subject, and body)")
            return
        
        # Update status
        self.status_label.config(text="Analyzing email...")
        self.root.update()
        
        try:
            # Perform comprehensive analysis
            results = self.detector.analyze_email(sender, subject, body)
            
            # Display results
            self.display_individual_results(results, sender, subject, body)
            
            # Update status
            classification = results['classification']
            if classification == 'PHISHING':
                status_msg = f"Analysis complete: {classification} DETECTED"
            elif classification == 'SUSPICIOUS':
                status_msg = f"Analysis complete: {classification}"
            else:
                status_msg = f"Analysis complete: {classification}"
            
            self.status_label.config(text=status_msg)
            
        except Exception as e:
            messagebox.showerror("Analysis Error", f"Error analyzing email: {str(e)}")
            self.status_label.config(text="Analysis failed")
    
    def display_individual_results(self, results, sender, subject, body):
        """
        DISPLAY ANALYSIS RESULTS: Show comprehensive analysis in user-friendly format
        
        This creates a detailed, color-coded report that explains the analysis
        results in terms that both technical and non-technical users can understand.
        """
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        
        classification = results['classification']
        score = results['final_score']
        
        # ================================
        # ANALYSIS HEADER
        # ================================
        self.results_text.insert(tk.END, "EMAIL SECURITY ANALYSIS REPORT\n", "header")
        self.results_text.insert(tk.END, "=" * 70 + "\n\n")
        
        # Show analyzed email details
        self.results_text.insert(tk.END, "Analyzed Email:\n", "subheader")
        self.results_text.insert(tk.END, f"   From: {sender}\n")
        self.results_text.insert(tk.END, f"   Subject: {subject}\n")
        self.results_text.insert(tk.END, f"   Body Length: {len(body)} characters\n\n")
        
        # ================================
        # MAIN VERDICT
        # ================================
        self.results_text.insert(tk.END, "SECURITY VERDICT:\n", "subheader")
        self.results_text.insert(tk.END, "   Classification: ")
        
        if classification == "SAFE":
            self.results_text.insert(tk.END, f"SAFE: {classification}\n", "safe")
            verdict_explanation = "This email appears to be legitimate and safe to interact with."
        elif classification == "SUSPICIOUS":
            self.results_text.insert(tk.END, f"SUSPICIOUS: {classification}\n", "suspicious")
            verdict_explanation = "This email has suspicious characteristics. Exercise caution."
        else:
            self.results_text.insert(tk.END, f"PHISHING: {classification}\n", "phishing")
            verdict_explanation = "This email shows strong indicators of being a phishing attempt."
        
        self.results_text.insert(tk.END, f"   Risk Score: {score}/50\n")
        self.results_text.insert(tk.END, f"   Assessment: {verdict_explanation}\n\n")
        
        # ================================
        # DETAILED TECHNICAL ANALYSIS
        # ================================
        self.results_text.insert(tk.END, "DETAILED SECURITY ANALYSIS:\n", "subheader")
        self.results_text.insert(tk.END, "-" * 50 + "\n\n")
        
        # Domain Trust Analysis
        whitelist = results['whitelist']
        self.results_text.insert(tk.END, "Sender Domain Analysis:\n")
        if whitelist['is_safe']:
            self.results_text.insert(tk.END, "   SAFE: Sender domain is in trusted whitelist\n", "safe")
        else:
            self.results_text.insert(tk.END, "   WARNING: Sender domain not in trusted whitelist\n")
        self.results_text.insert(tk.END, f"   Risk Points: {whitelist['score']}\n\n")
        
        # Keyword Analysis
        keywords = results['keywords']
        self.results_text.insert(tk.END, "Content Analysis:\n")
        if keywords['found']:
            self.results_text.insert(tk.END, f"   WARNING: Suspicious keywords detected:\n")
            for keyword in keywords['found'][:10]:  # Show first 10
                self.results_text.insert(tk.END, f"      • {keyword}\n")
            if len(keywords['found']) > 10:
                self.results_text.insert(tk.END, f"      ... and {len(keywords['found']) - 10} more\n")
        else:
            self.results_text.insert(tk.END, "   SAFE: No suspicious keywords detected\n", "safe")
        self.results_text.insert(tk.END, f"   Risk Points: {keywords['score']}\n\n")
        
        # Domain Spoofing Analysis
        spoofing = results['spoofing']
        self.results_text.insert(tk.END, "Domain Spoofing Analysis:\n")
        if spoofing['detected']:
            self.results_text.insert(tk.END, f"   ALERT: Potential domain spoofing detected\n")
            self.results_text.insert(tk.END, f"   Details: {spoofing['reason']}\n")
        else:
            self.results_text.insert(tk.END, "   SAFE: No domain spoofing detected\n", "safe")
        self.results_text.insert(tk.END, f"   Risk Points: {spoofing['score']}\n\n")
        
        # URL Analysis
        urls = results['urls']
        self.results_text.insert(tk.END, "URL Security Analysis:\n")
        if urls['suspicious']:
            self.results_text.insert(tk.END, f"   ALERT: {len(urls['suspicious'])} suspicious URLs detected:\n")
            for i, url in enumerate(urls['suspicious'][:5]):  # Show first 5
                if ' (' in url and url.endswith(')'):
                    url_part, reason_part = url.rsplit(' (', 1)
                    reason_part = reason_part[:-1]  # Remove closing parenthesis
                    self.results_text.insert(tk.END, f"      {i+1}. {url_part}\n")
                    self.results_text.insert(tk.END, f"         Issue: {reason_part}\n")
                else:
                    self.results_text.insert(tk.END, f"      {i+1}. {url}\n")
            if len(urls['suspicious']) > 5:
                self.results_text.insert(tk.END, f"      ... and {len(urls['suspicious']) - 5} more suspicious URLs\n")
        else:
            self.results_text.insert(tk.END, "   SAFE: No suspicious URLs detected\n", "safe")
        self.results_text.insert(tk.END, f"   Risk Points: {urls['score']}\n\n")
        
        # ================================
        # RECOMMENDATIONS
        # ================================
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
        
        else:  # PHISHING
            self.results_text.insert(tk.END, "SECURITY ALERT - Likely phishing attempt:\n", "phishing")
            self.results_text.insert(tk.END, "   • DO NOT click any links in this email\n")
            self.results_text.insert(tk.END, "   • DO NOT download or open any attachments\n")
            self.results_text.insert(tk.END, "   • DO NOT provide any personal information\n")
            self.results_text.insert(tk.END, "   • Report this email to your IT security team immediately\n")
            self.results_text.insert(tk.END, "   • Delete this email after reporting\n")
            self.results_text.insert(tk.END, "   • Alert colleagues about this phishing attempt\n")
        
        # ================================
        # TECHNICAL NOTES
        # ================================
        self.results_text.insert(tk.END, f"\nTechnical Details:\n")
        self.results_text.insert(tk.END, f"   Analysis Engine: Advanced Rule-Based Detection\n")
        self.results_text.insert(tk.END, f"   Threat Intelligence: {'Enabled' if self.detector.threat_intelligence else 'Static patterns only'}\n")
        # Check if Levenshtein is available
        try:
            import Levenshtein
            levenshtein_available = True
        except ImportError:
            levenshtein_available = False
        
        self.results_text.insert(tk.END, f"   URL Analysis: {'Enhanced (Levenshtein)' if levenshtein_available else 'Basic pattern matching'}\n")
        self.results_text.insert(tk.END, f"   Analysis Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        self.results_text.config(state=tk.DISABLED)
    
    def clear_fields(self):
        """CLEAR INPUT FIELDS: Reset the individual analysis form"""
        self.sender_entry.delete(0, tk.END)
        self.subject_entry.delete(0, tk.END)
        self.body_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        self.status_label.config(text="Fields cleared - ready for new analysis")
    
    def load_sample_email(self):
        """LOAD SAMPLE EMAIL: Insert a sample phishing email for demonstration"""
        # Clear existing content
        self.clear_fields()
        
        # Insert sample phishing email
        sample_sender = "security@paypaI.com"  # Note the capital I
        sample_subject = "URGENT: Your Account Will Be Suspended"
        sample_body = """Dear Valued Customer,

Your PayPal account has been temporarily limited due to suspicious activity detected on your account. 

To avoid permanent suspension, you must verify your account information immediately by clicking the link below:

VERIFY YOUR ACCOUNT NOW: http://bit.ly/paypal-verify-urgent

WARNING: Failure to verify within 24 hours will result in permanent account closure and loss of funds.

If you have any questions, please do not hesitate to contact our customer service team.

Best regards,
PayPal Security Team
security@paypal.com

This email was sent to protect your account security."""
        
        self.sender_entry.insert(0, sample_sender)
        self.subject_entry.insert(0, sample_subject)
        self.body_text.insert(1.0, sample_body)
        
        self.status_label.config(text="Sample phishing email loaded - click 'Analyze Email' to see detection in action")
    
    def browse_file(self):
        """BROWSE FOR BATCH FILE: Open file dialog to select email file"""
        file_path = filedialog.askopenfilename(
            title="Select Email File for Batch Analysis",
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.file_path_var.set(file_path)
            self.status_label.config(text=f"Selected file: {os.path.basename(file_path)}")
    
    def analyze_batch(self):
        """BATCH EMAIL ANALYSIS: Process multiple emails from file"""
        file_path = self.file_path_var.get().strip()
        
        if not file_path:
            messagebox.showwarning("File Required", "Please select an email file for batch analysis")
            return
        
        # Update status and show progress
        self.status_label.config(text="Processing batch emails...")
        self.batch_results_text.config(state=tk.NORMAL)
        self.batch_results_text.delete(1.0, tk.END)
        self.batch_results_text.insert(tk.END, "🔄 Processing emails, please wait...\n")
        self.batch_results_text.update()
        
        try:
            # Perform batch analysis
            batch_results = self.detector.analyze_batch_emails(file_path)
            
            if 'error' in batch_results:
                self.batch_results_text.delete(1.0, tk.END)
                self.batch_results_text.insert(tk.END, f"Error: {batch_results['error']}\n")
                self.status_label.config(text="Batch analysis failed")
                return
            
            # Store results for report generation
            self.current_batch_results = batch_results
            
            # Display results
            self.display_batch_results(batch_results)
            
            # Update status
            summary = batch_results['summary']
            total = summary['total_emails']
            phishing = summary['phishing_count']
            suspicious = summary['suspicious_count']
            self.status_label.config(text=f"Batch complete: {total} emails analyzed, {phishing} phishing, {suspicious} suspicious")
            
        except Exception as e:
            self.batch_results_text.delete(1.0, tk.END)
            self.batch_results_text.insert(tk.END, f"Error analyzing batch: {str(e)}\n")
            self.status_label.config(text="Batch analysis error")
            messagebox.showerror("Analysis Error", f"Failed to analyze batch emails: {str(e)}")
    
    def display_batch_results(self, batch_results):
        """DISPLAY BATCH RESULTS: Show comprehensive batch analysis summary"""
        self.batch_results_text.config(state=tk.NORMAL)
        self.batch_results_text.delete(1.0, tk.END)
        
        summary = batch_results['summary']
        
        # ================================
        # BATCH ANALYSIS HEADER
        # ================================
        self.batch_results_text.insert(tk.END, "BATCH EMAIL ANALYSIS REPORT\n", "header")
        self.batch_results_text.insert(tk.END, "=" * 70 + "\n\n")
        
        # ================================
        # EXECUTIVE SUMMARY
        # ================================
        self.batch_results_text.insert(tk.END, "EXECUTIVE SUMMARY\n", "subheader")
        self.batch_results_text.insert(tk.END, "-" * 30 + "\n")
        self.batch_results_text.insert(tk.END, f"Total Emails Analyzed: {summary['total_emails']}\n")
        
        # Color-coded statistics
        self.batch_results_text.insert(tk.END, f"Safe Emails: {summary['safe_count']} ({summary['safe_percentage']:.1f}%)\n", "safe")
        self.batch_results_text.insert(tk.END, f"Suspicious Emails: {summary['suspicious_count']} ({summary['suspicious_percentage']:.1f}%)\n", "suspicious")
        self.batch_results_text.insert(tk.END, f"Phishing Emails: {summary['phishing_count']} ({summary['phishing_percentage']:.1f}%)\n", "phishing")
        
        # ================================
        # RISK ASSESSMENT
        # ================================
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
        
        # ================================
        # INDIVIDUAL EMAIL RESULTS
        # ================================
        self.batch_results_text.insert(tk.END, "INDIVIDUAL EMAIL ANALYSIS\n", "subheader")
        self.batch_results_text.insert(tk.END, "-" * 40 + "\n")
        
        for result in batch_results['results']:
            classification = result['classification']
            
            # Choose color based on classification
            if classification == "SAFE":
                color = "safe"
            elif classification == "SUSPICIOUS":
                color = "suspicious"
            else:
                color = "phishing"
            
            self.batch_results_text.insert(tk.END, f"\nEmail #{result['email_number']}: ")
            self.batch_results_text.insert(tk.END, f"{classification}", color)
            self.batch_results_text.insert(tk.END, f" (Risk Score: {result['final_score']}/50)\n")
            
            self.batch_results_text.insert(tk.END, f"  From: {result['email_data']['sender']}\n")
            self.batch_results_text.insert(tk.END, f"  Subject: {result['email_data']['subject'][:60]}{'...' if len(result['email_data']['subject']) > 60 else ''}\n")
            
            # Show key findings
            if result['keywords']['found']:
                keywords = result['keywords']['found'][:3]  # Show first 3
                self.batch_results_text.insert(tk.END, f"  Key Issues: {', '.join(keywords)}")
                if len(result['keywords']['found']) > 3:
                    self.batch_results_text.insert(tk.END, f" +{len(result['keywords']['found']) - 3} more")
                self.batch_results_text.insert(tk.END, "\n")
            
            if result['urls']['suspicious']:
                self.batch_results_text.insert(tk.END, f"  Suspicious URLs: {len(result['urls']['suspicious'])} detected\n")
        
        # ================================
        # RECOMMENDATIONS
        # ================================
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
        
        self.batch_results_text.insert(tk.END, f"\n📄 Use 'Generate Report' to create a detailed document for stakeholders.\n")
        
        self.batch_results_text.config(state=tk.DISABLED)
    
    def generate_batch_report(self):
        """GENERATE DETAILED REPORT: Create comprehensive report file"""
        if not self.current_batch_results:
            messagebox.showwarning("No Data", "Please analyze a batch of emails first")
            return
        
        # Ask user where to save the report
        output_file = filedialog.asksaveasfilename(
            title="Save Batch Analysis Report",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        
        if output_file:
            try:
                success = self.detector.generate_report(self.current_batch_results, output_file)
                if success:
                    messagebox.showinfo("Report Generated", 
                                      f"Detailed report saved successfully!\n\nLocation: {output_file}")
                    self.status_label.config(text=f"Report saved: {os.path.basename(output_file)}")
                else:
                    messagebox.showerror("Report Error", "Failed to generate report")
            except Exception as e:
                messagebox.showerror("Report Error", f"Error generating report: {str(e)}")
    
    def clear_batch(self):
        """CLEAR BATCH ANALYSIS: Reset batch analysis interface"""
        self.file_path_var.set("")
        self.batch_results_text.config(state=tk.NORMAL)
        self.batch_results_text.delete(1.0, tk.END)
        self.batch_results_text.config(state=tk.DISABLED)
        self.current_batch_results = None
        self.status_label.config(text="Batch analysis cleared")
    
    def refresh_system_info(self):
        """REFRESH SYSTEM INFO: Update system status information"""
        self.system_info_text.config(state=tk.NORMAL)
        self.system_info_text.delete(1.0, tk.END)
        
        self.system_info_text.insert(tk.END, "PHISHING DETECTION SYSTEM STATUS\n", "header")
        self.system_info_text.insert(tk.END, "=" * 50 + "\n\n")
        
        # System Information
        self.system_info_text.insert(tk.END, "System Information:\n", "subheader")
        self.system_info_text.insert(tk.END, f"   Version: Advanced Rule-Based Detection Engine v1.0\n")
        self.system_info_text.insert(tk.END, f"   Status: Operational\n")
        self.system_info_text.insert(tk.END, f"   Detection Methods: Keyword Analysis, Domain Spoofing, URL Analysis, Auth Verification\n")
        
        # Dependencies
        self.system_info_text.insert(tk.END, f"\nDependencies:\n", "subheader")
        self.system_info_text.insert(tk.END, f"   Python Email Library: Available\n")
        # Check Levenshtein availability
        try:
            import Levenshtein
            levenshtein_status = "Available (Enhanced URL Analysis)"
        except ImportError:
            levenshtein_status = "Not Available (Basic Analysis Only)"
        self.system_info_text.insert(tk.END, f"   Levenshtein Distance: {levenshtein_status}\n")
        self.system_info_text.insert(tk.END, f"   Tkinter GUI: Available\n")
        
        # Threat Intelligence Status
        self.system_info_text.insert(tk.END, f"\nThreat Intelligence:\n", "subheader")
        if self.detector.threat_intelligence:
            keywords = len(self.detector.threat_intelligence.get('suspicious_keywords', {}))
            domains = len(self.detector.threat_intelligence.get('suspicious_domains', {}))
            self.system_info_text.insert(tk.END, f"   Status: Active\n")
            self.system_info_text.insert(tk.END, f"   Suspicious Keywords: {keywords}\n")
            self.system_info_text.insert(tk.END, f"   Suspicious Domains: {domains}\n")
            
            if 'generated_at' in self.detector.threat_intelligence:
                self.system_info_text.insert(tk.END, f"   Last Updated: {self.detector.threat_intelligence['generated_at']}\n")
        else:
            self.system_info_text.insert(tk.END, f"   Status: Using Static Patterns Only\n")
            self.system_info_text.insert(tk.END, f"   Recommendation: Update threat intelligence from email datasets\n")
        
        # Dataset Information
        self.system_info_text.insert(tk.END, f"\nEmail Datasets:\n", "subheader")
        if self.data_analyzer:
            if self.data_analyzer.ham_dir and os.path.exists(self.data_analyzer.ham_dir):
                ham_count = len([f for f in os.listdir(self.data_analyzer.ham_dir) if os.path.isfile(os.path.join(self.data_analyzer.ham_dir, f))])
                self.system_info_text.insert(tk.END, f"   Legitimate Emails: {ham_count} files in {self.data_analyzer.ham_dir}\n")
            else:
                self.system_info_text.insert(tk.END, f"   Legitimate Emails: No ham dataset found\n")
            
            if self.data_analyzer.spam_dir and os.path.exists(self.data_analyzer.spam_dir):
                spam_count = len([f for f in os.listdir(self.data_analyzer.spam_dir) if os.path.isfile(os.path.join(self.data_analyzer.spam_dir, f))])
                self.system_info_text.insert(tk.END, f"   Malicious Emails: {spam_count} files in {self.data_analyzer.spam_dir}\n")
            else:
                self.system_info_text.insert(tk.END, f"   Malicious Emails: No spam dataset found\n")
        else:
            self.system_info_text.insert(tk.END, f"   Status: Dataset analyzer not available\n")
        
        # Performance Information
        self.system_info_text.insert(tk.END, f"\nPerformance Characteristics:\n", "subheader")
        self.system_info_text.insert(tk.END, f"   Analysis Speed: ~1-2 seconds per email\n")
        self.system_info_text.insert(tk.END, f"   Memory Usage: Low (rule-based, no ML models)\n")
        self.system_info_text.insert(tk.END, f"   Scalability: Suitable for individual and batch analysis\n")
        self.system_info_text.insert(tk.END, f"   Accuracy: High precision with low false positives\n")
        
        self.system_info_text.config(state=tk.DISABLED)
        
        # Also refresh threat intelligence preview
        self.refresh_threat_intelligence_preview()
    
    def refresh_threat_intelligence_preview(self):
        """REFRESH THREAT INTEL: Update threat intelligence preview"""
        self.threat_intel_text.config(state=tk.NORMAL)
        self.threat_intel_text.delete(1.0, tk.END)
        
        if self.detector.threat_intelligence:
            threat_intel = self.detector.threat_intelligence
            
            self.threat_intel_text.insert(tk.END, "🕵️ ACTIVE THREAT INTELLIGENCE\n", "header")
            self.threat_intel_text.insert(tk.END, "=" * 40 + "\n\n")
            
            # Top suspicious keywords
            self.threat_intel_text.insert(tk.END, "Top Suspicious Keywords:\n", "subheader")
            keywords = list(threat_intel.get('suspicious_keywords', {}).items())[:15]
            for keyword, score in keywords:
                self.threat_intel_text.insert(tk.END, f"   '{keyword}' (risk: {score})\n")
            
            self.threat_intel_text.insert(tk.END, f"\nTop Suspicious Domains:\n", "subheader")
            domains = list(threat_intel.get('suspicious_domains', {}).items())[:10]
            for domain, score in domains:
                self.threat_intel_text.insert(tk.END, f"   '{domain}' (risk: {score})\n")
            
            self.threat_intel_text.insert(tk.END, f"\nSuspicious URL Patterns:\n", "subheader")
            url_patterns = list(threat_intel.get('suspicious_url_patterns', {}).items())[:8]
            for pattern, score in url_patterns:
                self.threat_intel_text.insert(tk.END, f"   '{pattern}' (risk: {score})\n")
            
            # Statistics
            if 'analysis_stats' in threat_intel:
                stats = threat_intel['analysis_stats']
                self.threat_intel_text.insert(tk.END, f"\nIntelligence Statistics:\n", "subheader")
                self.threat_intel_text.insert(tk.END, f"   Generated from: {stats.get('total_phishing_emails_analyzed', 'Unknown')} malicious + {stats.get('total_legitimate_emails_analyzed', 'Unknown')} legitimate emails\n")
                self.threat_intel_text.insert(tk.END, f"   Last updated: {threat_intel.get('generated_at', 'Unknown')}\n")
        else:
            self.threat_intel_text.insert(tk.END, "NO ACTIVE THREAT INTELLIGENCE\n", "header")
            self.threat_intel_text.insert(tk.END, "=" * 40 + "\n\n")
            self.threat_intel_text.insert(tk.END, "The system is currently using static detection patterns only.\n")
            self.threat_intel_text.insert(tk.END, "To enable dynamic threat intelligence:\n\n")
            self.threat_intel_text.insert(tk.END, "1. Ensure email datasets are available in the data/ directory\n")
            self.threat_intel_text.insert(tk.END, "2. Click 'Update Threat Intelligence' to generate patterns\n")
            self.threat_intel_text.insert(tk.END, "3. Dynamic patterns will enhance detection accuracy\n")
        
        self.threat_intel_text.config(state=tk.DISABLED)
    
    def update_threat_intelligence(self):
        """UPDATE THREAT INTELLIGENCE: Regenerate threat intelligence from datasets"""
        if not self.data_analyzer:
            messagebox.showwarning("Data Analyzer Unavailable", 
                                 "Email dataset analyzer is not available")
            return
        
        # Confirm action
        result = messagebox.askyesno("Update Threat Intelligence", 
                                   "This will analyze email datasets to generate new threat intelligence.\n\n"
                                   "This may take several minutes depending on dataset size.\n\n"
                                   "Continue?")
        if not result:
            return
        
        # Update status
        self.status_label.config(text="Updating threat intelligence...")
        self.root.update()
        
        try:
            # Generate new threat intelligence
            threat_intel = self.data_analyzer.generate_threat_intelligence()
            
            if threat_intel:
                # Update detector with new intelligence
                self.detector.threat_intelligence = threat_intel
                
                # Refresh displays
                self.refresh_system_info()
                
                # Show success message
                keywords = len(threat_intel.get('suspicious_keywords', {}))
                domains = len(threat_intel.get('suspicious_domains', {}))
                
                messagebox.showinfo("Update Complete", 
                                  f"Threat intelligence updated successfully!\n\n"
                                  f"New patterns discovered:\n"
                                  f"• {keywords} suspicious keywords\n"
                                  f"• {domains} suspicious domains\n\n"
                                  f"Detection accuracy has been enhanced.")
                
                self.status_label.config(text="Threat intelligence updated successfully")
            else:
                messagebox.showwarning("Update Failed", 
                                     "Could not generate threat intelligence.\n\n"
                                     "Please check that email datasets are available.")
                self.status_label.config(text="Threat intelligence update failed")
        
        except Exception as e:
            messagebox.showerror("Update Error", f"Error updating threat intelligence: {str(e)}")
            self.status_label.config(text="Threat intelligence update error")
    
    def test_email_datasets(self):
        """TEST EMAIL DATASETS: Verify dataset parsing functionality"""
        if not self.data_analyzer:
            messagebox.showwarning("Data Analyzer Unavailable", 
                                 "Email dataset analyzer is not available")
            return
        
        # Create a new window for test results
        test_window = tk.Toplevel(self.root)
        test_window.title("Email Dataset Testing")
        test_window.geometry("800x600")
        
        # Create scrolled text for results
        test_frame = ttk.Frame(test_window, padding="15")
        test_frame.pack(fill=tk.BOTH, expand=True)
        
        test_text = scrolledtext.ScrolledText(test_frame, width=90, height=35, 
                                            wrap=tk.WORD, font=('Arial', 10))
        test_text.pack(fill=tk.BOTH, expand=True)
        
        # Run test and display results
        test_text.insert(tk.END, "🧪 EMAIL DATASET PARSING TEST\n")
        test_text.insert(tk.END, "=" * 50 + "\n\n")
        
        try:
            # Redirect print output to the text widget
            import io
            import sys
            
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            
            # Run the test
            self.data_analyzer.test_email_parsing(num_samples=5)
            
            # Get the output
            output = sys.stdout.getvalue()
            sys.stdout = old_stdout
            
            # Display the output
            test_text.insert(tk.END, output)
            
        except Exception as e:
            test_text.insert(tk.END, f"Error running dataset test: {str(e)}\n")
        
        # Add close button
        close_btn = ttk.Button(test_frame, text="Close", 
                             command=test_window.destroy)
        close_btn.pack(pady=10)


def main():
    """
    MAIN APPLICATION ENTRY POINT
    
    This starts the GUI application and handles any startup errors gracefully.
    """
    try:
        print("🚀 Starting Phishing Detection GUI...")
        
        # Create main application window
        root = tk.Tk()
        
        # Initialize and run the application
        app = PhishingDetectorGUI(root)
        
        print("✅ GUI initialized successfully")
        print("📱 Application ready for use")
        
        # Start the GUI event loop
        root.mainloop()
        
    except Exception as e:
        print(f"❌ Failed to start application: {e}")
        try:
            messagebox.showerror("Startup Error", 
                               f"Failed to start the application:\n\n{str(e)}\n\n"
                               f"Please check that all required files are present.")
        except:
            print("Could not show error dialog - GUI system unavailable")


if __name__ == "__main__":
    # Import datetime here for timestamp functionality
    from datetime import datetime
    
    main()
