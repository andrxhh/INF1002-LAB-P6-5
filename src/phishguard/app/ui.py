#!/usr/bin/env python3
"""
=============================================================================
                     PHISHGUARD GUI - BEGINNER FRIENDLY VERSION
=============================================================================

This is the main user interface for the PhishGuard email security system.

WHAT THIS FILE DOES:
- Creates a simple window where users can analyze emails for phishing threats
- Has two main tabs: Individual Analysis and Batch Analysis  
- Shows results in easy-to-understand, color-coded format

MAIN COMPONENTS:
1. PhishingDetectorGUI class - The main window and interface
2. Individual Analysis tab - Analyze one email at a time
3. Batch Analysis tab - Process multiple emails from files
4. Helper functions - Load files, display results, etc.

HOW TO USE:
- Run this file to open the GUI
- Paste email content or load from files
- Click "Analyze Email" to check for phishing threats
- Read the color-coded results and recommendations
"""

# ============================================================================
#                              IMPORTS
# ============================================================================
import tkinter as tk                    # For creating the GUI window
from tkinter import ttk                 # For modern GUI widgets
from tkinter import scrolledtext        # For text areas with scrollbars
from tkinter import messagebox          # For popup error/info messages
from tkinter import filedialog          # For file open/save dialogs
import os                              # For file operations
import sys                             # For system operations
from pathlib import Path               # For handling file paths

# ============================================================================
#                           PYTHON PATH SETUP
# ============================================================================
# Add the src directory to Python path so we can import phishguard modules
# This is needed when running the GUI directly
project_root = Path(__file__).parent.parent.parent.parent  # Go up to project root
src_path = project_root / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# ============================================================================
#                        IMPORT PHISHGUARD COMPONENTS
# ============================================================================
# Import our phishing detection components
try:
    from phishguard.app.detector import PhishingDetector
    from phishguard.schema import EmailRecord
    print("✅ Successfully imported PhishGuard components")
except ImportError as e:
    messagebox.showerror("Import Error", f"Could not import required modules: {e}")
    sys.exit(1)


# ============================================================================
#                           MAIN GUI CLASS
# ============================================================================

class PhishingDetectorGUI:
    """
    ==========================================================================
                            MAIN GUI APPLICATION CLASS
    ==========================================================================
    
    This is the main class that creates and manages the PhishGuard GUI window.
    
    WHAT IT DOES:
    - Creates a window with tabs for different functions
    - Handles user input (email text, file uploads)
    - Calls the phishing detector to analyze emails
    - Shows results in a user-friendly format
    
    THE TWO MAIN TABS:
    1. 📧 Individual Analysis - Check one email at a time
    2. 📁 Batch Analysis - Check multiple emails from files
    
    BEGINNER TIP: 
    Think of this like the "control panel" for our email security system!
    """
    
    def __init__(self, root):
        """
        INITIALIZE THE GUI APPLICATION
        
        This sets up everything needed for the GUI to work:
        1. Save the main window reference
        2. Initialize the phishing detection engine
        3. Create the user interface
        
        Args:
            root: The main tkinter window (passed from main() function)
        """
        print("🚀 Setting up PhishGuard GUI...")
        
        # STEP 1: Save reference to the main window
        self.root = root
        
        # STEP 2: Initialize the phishing detection engine
        print("🔄 Starting phishing detection system...")
        try:
            self.detector = PhishingDetector()  # This does the actual email analysis
            print("✅ Phishing detector ready!")
        except Exception as e:
            # If detector fails to load, show error and exit
            messagebox.showerror("Startup Error", 
                               f"Failed to start phishing detector: {e}")
            sys.exit(1)
        
        # STEP 3: Storage for batch analysis results
        self.current_batch_results = None  # Stores results when analyzing multiple emails
        
        # STEP 4: Build the user interface
        print("🎨 Creating user interface...")
        self.setup_ui()
        print("✅ GUI ready for use!")
    
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
        
        notebook.add(self.individual_frame, text="Individual Analysis")
        notebook.add(self.batch_frame, text="Batch Analysis")
        
        # Setup each tab
        self.setup_individual_tab()
        self.setup_batch_tab()
        
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
                             text="Tip: Copy and paste email content above, or use 'Load from File' for .eml, .mbox, .txt files",
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
        
        # Load from file button
        load_file_btn = ttk.Button(button_frame, text="Load from File", 
                                 command=self.load_email_from_file)
        load_file_btn.pack(side=tk.LEFT, padx=10)
        
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
                                text="Supported Formats:\n"
                                     "• Text files (.txt) - Multiple emails separated by '---' or 'EMAIL:' dividers\n"
                                     "• Unix Mailbox (.mbox) - Standard Unix mbox format with multiple emails\n"
                                     "• Email Message (.eml) - Individual RFC822 email message files\n"
                                     "• Outlook Message (.msg) - Microsoft Outlook message files",
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
        # DETAILED ANALYSIS
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
        self.results_text.insert(tk.END, f"   Analysis Engine: PhishGuard Rule-Based Detection\n")
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
    
    def load_email_from_file(self):
        """LOAD EMAIL FROM FILE: Load individual email from various file formats"""
        file_path = filedialog.askopenfilename(
            title="Load Email from File",
            filetypes=[
                ("Email files", "*.txt;*.mbox;*.eml;*.msg"),
                ("Text files", "*.txt"),
                ("Unix Mailbox", "*.mbox"),  
                ("Email Message", "*.eml"),
                ("Outlook Message", "*.msg"),
                ("All files", "*.*")
            ]
        )
        
        if not file_path:
            return
            
        try:
            # Use the ingestion system to parse the email
            from phishguard.ingestion.loaders import iterate_emails
            from phishguard.normalize.parse_mime import normalize_header, decode_address, extract_body
            
            # Get the first email from the file
            email_loaded = False
            for path, email_msg in iterate_emails(file_path):
                try:
                    # Use your friend's functions directly to extract email data
                    
                    # Extract headers using your friend's function
                    headers_dict = normalize_header(email_msg)
                    subject = headers_dict.get('subject', '')
                    
                    # Extract addresses using your friend's function
                    from_display, from_addr, reply_to_addr = decode_address(email_msg)
                    
                    # Extract body content using your friend's function
                    body_text, body_html = extract_body(email_msg)
                    
                    # Clear existing content
                    self.clear_fields()
                    
                    # Load email data into the form
                    self.sender_entry.insert(0, from_addr or '')
                    self.subject_entry.insert(0, subject or '')
                    
                    # Use body_text, or extract from body_html if no text version
                    body_content = body_text or ''
                    if not body_content and body_html:
                        # Simple HTML to text conversion for display
                        import re
                        body_content = re.sub(r'<[^>]+>', '', body_html)
                        body_content = body_content.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
                    
                    self.body_text.insert(1.0, body_content)
                    
                    # Update status
                    filename = os.path.basename(file_path)
                    self.status_label.config(text=f"Email loaded from {filename} - ready for analysis")
                    email_loaded = True
                    break  # Only load the first email for individual analysis
                    
                except Exception as e:
                    print(f"Error parsing email: {e}")
                    continue
            
            if not email_loaded:
                messagebox.showerror("Load Error", 
                                   f"Could not load email from file: {os.path.basename(file_path)}\n\n"
                                   f"Please ensure the file contains a valid email message.")
                self.status_label.config(text="Failed to load email from file")
        
        except Exception as e:
            messagebox.showerror("Load Error", f"Error loading email file: {str(e)}")
            self.status_label.config(text="Error loading email file")
    
    def browse_file(self):
        """BROWSE FOR BATCH FILE: Open file dialog to select email file"""
        file_path = filedialog.askopenfilename(
            title="Select Email File for Batch Analysis",
            filetypes=[
                ("Email files", "*.txt;*.mbox;*.eml;*.msg"),
                ("Text files", "*.txt"),
                ("Unix Mailbox", "*.mbox"),
                ("Email Message", "*.eml"),
                ("Outlook Message", "*.msg"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.file_path_var.set(file_path)
            # Determine file type for better user feedback
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext == '.mbox':
                file_type = "Unix mailbox file"
            elif file_ext == '.eml':
                file_type = "Email message file"
            elif file_ext == '.msg':
                file_type = "Outlook message file"
            elif file_ext == '.txt':
                file_type = "Text file"
            else:
                file_type = "Email file"
            
            self.status_label.config(text=f"Selected {file_type}: {os.path.basename(file_path)}")
    
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
    


# ============================================================================
#                           MAIN APPLICATION ENTRY POINT
# ============================================================================

def main():
    """
    START THE PHISHGUARD GUI APPLICATION
    
    This is the function that gets called when you run this file.
    It creates the main window and starts the GUI.
    
    WHAT HAPPENS:
    1. Create the main tkinter window
    2. Initialize the PhishingDetectorGUI class
    3. Start the GUI event loop (waits for user input)
    4. Handle any startup errors gracefully
    """
    try:
        print("🚀 Starting PhishGuard Email Security GUI...")
        
        # STEP 1: Create the main application window
        root = tk.Tk()
        
        # STEP 2: Initialize our GUI application
        app = PhishingDetectorGUI(root)
        
        print("✅ GUI initialized successfully")
        print("📱 PhishGuard is ready! Look for the GUI window on your screen.")
        
        # STEP 3: Start the GUI event loop (this keeps the window open)
        root.mainloop()
        
    except Exception as e:
        # If something goes wrong during startup, show a helpful error
        print(f"❌ Failed to start PhishGuard: {e}")
        try:
            messagebox.showerror("Startup Error", 
                               f"PhishGuard failed to start:\n\n{str(e)}\n\n"
                               f"Please check that all required files are present.")
        except:
            print("Could not show error dialog - GUI system unavailable")


# ============================================================================
#                              RUN THE APPLICATION
# ============================================================================

if __name__ == "__main__":
    # Import datetime here for timestamp functionality (used in results)
    from datetime import datetime
    
    print("=" * 60)
    print("           PHISHGUARD EMAIL SECURITY SYSTEM")
    print("=" * 60)
    print("Starting GUI application...")
    print()
    
    # Start the application
    main()
