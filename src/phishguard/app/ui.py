# PhishGuard UI Module
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import filedialog
import os
import sys
from pathlib import Path

# Project path setup
project_root = Path(__file__).parent.parent.parent.parent
src_path = project_root / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# PhishGuard imports
try:
    from phishguard.app.detector_engine import PhishingDetector
    from phishguard.app.results_display import ResultsDisplayManager
except ImportError as e:
    messagebox.showerror("Import Error", str(e))
    sys.exit(1)
class PhishingDetectorGUI:
    
    def __init__(self, root):
        self.root = root
        
        try:
            # Initialize the simplified detector engine
            self.detector = PhishingDetector()
        except Exception as e:
            messagebox.showerror("Startup Error", str(e))
            sys.exit(1)
        
        self.current_batch_results = None
        self.setup_ui()
    def setup_ui(self):
        self.root.title("PhishGuard - Email Detection System")
        self.root.geometry("1000x800")
        self.root.configure(bg='#f0f0f0')
        
        # Window icon setup
        try:
            # Try to find the logo file in the app directory for window icon
            icon_path = Path(__file__).parent / 'App Logo.png'
            if icon_path.exists():
                icon_photo = tk.PhotoImage(file=str(icon_path))
                self.root.iconphoto(False, icon_photo)
            else:
                # Try current directory as fallback
                icon_photo = tk.PhotoImage(file='App Logo.png')
                self.root.iconphoto(False, icon_photo)
        except Exception:
            pass
        
        # GUI style/theme
        style = ttk.Style() 
        style.theme_use('classic')
        
        #main frame
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        header_frame.columnconfigure(1, weight=1)
        
        #logo
        try:
            # Try to find the logo file in the app directory
            logo_path = Path(__file__).parent / 'App Logo.png'
            if logo_path.exists():
                self.logo_photo = tk.PhotoImage(file=str(logo_path))
            else:
                # Fallback: try current directory
                self.logo_photo = tk.PhotoImage(file='App Logo.png')
            
            # Get original dimensions
            logo_width = self.logo_photo.width()
            logo_height = self.logo_photo.height()
            
            # Scale logo to fit nicely (max 60x60 pixels)
            max_size = 60
            if logo_width > max_size or logo_height > max_size:
                scale_factor = min(max_size/logo_width, max_size/logo_height)
                subsample_factor = max(1, int(1/scale_factor))
                self.logo_photo = self.logo_photo.subsample(subsample_factor)
            
            logo_label = ttk.Label(header_frame, image=self.logo_photo)
            logo_label.grid(row=0, column=0, rowspan=2, sticky=tk.W, padx=(0, 15))
            
        except Exception:
            # Fallback: show text if image fails
            logo_label = ttk.Label(header_frame, text="PhishGuard", font=('Arial', 12, 'bold'))
            logo_label.grid(row=0, column=0, rowspan=2, sticky=tk.W, padx=(0, 15))
        
        #title/header
        title_label = ttk.Label(header_frame, 
                               text="PhishGuard Email Detection System", 
                               font=('Arial', 18, 'bold'))
        title_label.grid(row=0, column=1, sticky=tk.W)
        
        #====================================
        #        Setup UI (tabs)            =
        #====================================  
        # Create tabbed interface (notebook widget)
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        main_frame.rowconfigure(1, weight=1)
        
        # Create frames 
        self.individual_frame = ttk.Frame(notebook, padding="15")
        self.batch_frame = ttk.Frame(notebook, padding="15")
        
        # Add tabs to the notebook with labels
        notebook.add(self.individual_frame, text="Individual Analysis")
        notebook.add(self.batch_frame, text="Batch Analysis")
        
        # Setup the content for each tab
        self.setup_individual_tab()
        self.setup_batch_tab()
    
    def setup_individual_tab(self):
        # Configure the main tab to expand the second column (input fields)
        self.individual_frame.columnconfigure(1, weight=1)
        
        #====================================
        # Setup UI (individual analysis tab) =
        #====================================  
        # labeled frame for email input
        input_frame = ttk.LabelFrame(self.individual_frame, text="Email Details", padding="15")
        input_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 15))
        input_frame.columnconfigure(1, weight=1)  # Make input fields expandable
        
        # Sender Email section
        ttk.Label(input_frame, text="Sender Email:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky="w", pady=5)
        self.sender_entry = ttk.Entry(input_frame, width=60, font=('Arial', 10))  # Text input for sender
        self.sender_entry.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=5)
        
        # Subject Line section
        ttk.Label(input_frame, text="Subject:", font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky="w", pady=5)
        self.subject_entry = ttk.Entry(input_frame, width=60, font=('Arial', 10))  # Text input for subject
        self.subject_entry.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=5)
        
        # Email Body Input Section
        ttk.Label(input_frame, text="Email Body:", font=('Arial', 10, 'bold')).grid(row=2, column=0, sticky="nw", pady=5)
        self.body_text = scrolledtext.ScrolledText(input_frame, width=70, height=10,   # Large text area with scrollbar
                                                  wrap=tk.WORD, font=('Arial', 10))
        self.body_text.grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=5)
        
        # Button Section
        # ==============
        # Frame for buttons
        button_frame = ttk.Frame(self.individual_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=15)
        
        # Analyze Email Button
        analyze_btn = ttk.Button(button_frame, text="Analyze Email", 
                               command=self.analyze_email)
        analyze_btn.pack(side=tk.LEFT, padx=10)
        
        # Clear Fields Button
        clear_btn = ttk.Button(button_frame, text="Clear Fields", 
                             command=self.clear_fields)
        clear_btn.pack(side=tk.LEFT, padx=10)
        
        # Load Sample Button 
        sample_btn = ttk.Button(button_frame, text="Load Sample", 
                              command=self.load_sample_email)
        sample_btn.pack(side=tk.LEFT, padx=10)
        
        # Results Display Section
        # ==============================
        # Large text area to show analysis results
        results_frame = ttk.LabelFrame(self.individual_frame, text="Analysis Results", padding="15")
        results_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(15, 0))
        results_frame.columnconfigure(0, weight=1)  # Make results area expandable
        results_frame.rowconfigure(0, weight=1)     # Make results area expandable vertically
        
        # Scrollable text widget
        self.results_text = scrolledtext.ScrolledText(results_frame, width=90, height=20, 
                                                     wrap=tk.WORD, state=tk.DISABLED, font=('Arial', 10))
        self.results_text.grid(row=0, column=0, sticky="nsew")
        
        # Resizing fix for results area
        self.individual_frame.rowconfigure(2, weight=1)
    
    def setup_batch_tab(self):
        # Configure the main tab to expand the second column (file path field)
        self.batch_frame.columnconfigure(1, weight=1)
        
        # File/Folder Selection Section
        # =============================
        # Frames for file/folder selection
        file_frame = ttk.LabelFrame(self.batch_frame, text="File or Folder Selection", padding="15")
        file_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 15))
        file_frame.columnconfigure(1, weight=1)  # Make file path field expandable
        
        # File/Folder Path Input and Browse Button
        ttk.Label(file_frame, text="Email Source:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky="w", pady=5)
        self.file_path_var = tk.StringVar()  # Variable to store selected file/folder path
        self.file_path_entry = ttk.Entry(file_frame, textvariable=self.file_path_var,   # Display selected path
                                        width=60, state='readonly', font=('Arial', 10))  # Read-only (user can't type)
        self.file_path_entry.grid(row=0, column=1, sticky="ew", padx=(10, 10), pady=5)
        
        # Single Browse Button that handles both files and folders
        browse_btn = ttk.Button(file_frame, text="Browse", command=self.browse_source)
        browse_btn.grid(row=0, column=2, pady=5)
        
        # supported file formats for uploading
        instructions = ttk.Label(file_frame, 
                                text="Click Browse to select:\n"
                                     "- Email files (.txt, .mbox) - or -\n"
                                     "- Folders containing email files\n"
                                     "The system automatically detects and processes all valid emails",
                                font=('Arial', 9), foreground='gray')
        instructions.grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=(10, 0))
        
        # Batch Action Buttons
        # ===========================
        # Frame for buttons
        batch_button_frame = ttk.Frame(self.batch_frame)
        batch_button_frame.grid(row=1, column=0, columnspan=2, pady=15)
        
        # Analyze Batch Button
        analyze_batch_btn = ttk.Button(batch_button_frame, text="Analyze Batch", 
                                     command=self.analyze_batch)
        analyze_batch_btn.pack(side=tk.LEFT, padx=10)
        
        # Save Results Button
        save_results_btn = ttk.Button(batch_button_frame, text="Save Results", 
                                    command=self.save_batch_results)
        save_results_btn.pack(side=tk.LEFT, padx=10)
        
        # Clear Button
        clear_batch_btn = ttk.Button(batch_button_frame, text="Clear", 
                                   command=self.clear_batch)
        clear_batch_btn.pack(side=tk.LEFT, padx=10)
        
        # Batch Results Section
        # ====================================
        # batch analysis results
        batch_results_frame = ttk.LabelFrame(self.batch_frame, text="Batch Analysis Results", padding="15")
        batch_results_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(15, 0))
        batch_results_frame.columnconfigure(0, weight=1)  # Make results area expandable
        batch_results_frame.rowconfigure(0, weight=1)     # Make results area expandable vertically
        
        # Scrollable text widget
        self.batch_results_text = scrolledtext.ScrolledText(batch_results_frame, width=90, height=20, 
                                                           wrap=tk.WORD, state=tk.DISABLED, font=('Arial', 10))
        self.batch_results_text.grid(row=0, column=0, sticky="nsew")
        
        # Initialize results display manager
        self.results_display = ResultsDisplayManager(self.results_text, self.batch_results_text)
        
        # Resizing fix for results area
        self.batch_frame.rowconfigure(2, weight=1)
    
    # ====================================
    # Individual Analysis Functions      =
    # ====================================
    
    def analyze_email(self):
        # Get user input from the form fields
        sender = self.sender_entry.get().strip()    # Remove extra spaces
        subject = self.subject_entry.get().strip()  # Remove extra spaces  
        body = self.body_text.get(1.0, tk.END).strip()  # Get all text from multiline field
        
        # error message if all fields are not filled
        if not sender or not subject or not body:
            messagebox.showwarning("Input Required", 
                                 "Please fill in all fields (sender, subject, and body)")
            return
        
        # Update the UI to show it's processing
        self.root.update()
        
        try:
            # Use detector engine
            email_record, total_score, rule_hits = self.detector.analyze_email(sender, subject, body)
            
            # Display the results using simplified display
            self.results_display.display_individual_results(email_record, total_score, rule_hits, self.detector.config)
            
        except Exception as e:
            # Show error message if analysis fails
            messagebox.showerror("Analysis Error", f"Error analyzing email: {str(e)}")
    
    
    def clear_fields(self):
        # Clear all input fields
        self.sender_entry.delete(0, tk.END)         # Clear sender field
        self.subject_entry.delete(0, tk.END)        # Clear subject field
        self.body_text.delete(1.0, tk.END)          # Clear body text area
        
        # Clear results display area
        self.results_text.config(state=tk.NORMAL)   # Enable editing temporarily
        self.results_text.delete(1.0, tk.END)       # Delete all results text
        self.results_text.config(state=tk.DISABLED) # Disable editing again
    
    def load_sample_email(self):
        # Clear all existing content
        self.clear_fields()
        
        # Sample phishing email data - when button is clicked this is the email that will be loaded
        # This sample demonstrates pipeline integration with a realistic phishing attempt
        sample_sender = "security@paypaI.com"  # Note the 'I' instead of 'l' - common spoofing technique
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
        
        # Insert sample data into the form fields
        self.sender_entry.insert(0, sample_sender)   # Fill sender field
        self.subject_entry.insert(0, sample_subject) # Fill subject field
        self.body_text.insert(1.0, sample_body)      # Fill body text area
    
    
    # ====================================
    # Batch Analysis Functions          =
    # ====================================
    
    def browse_source(self):
        """Smart browse function that lets user choose between file or folder"""
        from tkinter import messagebox
        
        # Ask user what they want to select
        choice = messagebox.askyesnocancel(
            "Select Source Type",
            "What would you like to select?\n\n"
            "- Click 'Yes' to select an email file (.txt, .mbox)\n"
            "- Click 'No' to select a folder containing email files\n"
            "- Click 'Cancel' to abort"
        )
        
        if choice is True:
            # User chose to select a file
            self._browse_file()
        elif choice is False:
            # User chose to select a folder
            self._browse_folder()
        # If choice is None, user clicked Cancel - do nothing
    
    def _browse_file(self):
        """Browse and select a single email file"""
        # Show file selection dialog with supported file types
        file_path = filedialog.askopenfilename(
            title="Select Email File for Batch Analysis",
            filetypes=[
                ("All Email Files", "*.txt;*.mbox"),  # Show all email files
                ("Text files", "*.txt"),              # Plain text files
                ("Unix Mailbox", "*.mbox"),           # Unix mailbox format
                ("All files", "*.*")                  # All files (fallback)
            ]
        )
        
        # If user selected a file (didn't cancel)
        if file_path:
            # Store the selected file path
            self.file_path_var.set(file_path)
    
    def _browse_folder(self):
        """Browse and select a folder containing email files"""
        # Show folder selection dialog
        folder_path = filedialog.askdirectory(
            title="Select Folder Containing Email Files"
        )
        
        # If user selected a folder (didn't cancel)
        if folder_path:
            # Store the selected folder path
            self.file_path_var.set(folder_path)
            
    
    def analyze_batch(self):
        # Get the selected file/folder path from the selection field
        source_path = self.file_path_var.get().strip()
        
        # Validate that a file or folder has been selected
        if not source_path:
            messagebox.showwarning("Source Required", 
                                 "Please select an email file or folder using the Browse buttons")
            return
        
        # Check if the selected path exists
        import os
        if not os.path.exists(source_path):
            messagebox.showerror("Path Not Found", 
                               f"The selected path does not exist:\n{source_path}")
            return
        
        # Determine if it's a file or folder and show appropriate message
        if os.path.isfile(source_path):
            source_type = "file"
            status_msg = f"Analyzing email file: {os.path.basename(source_path)}"
        elif os.path.isdir(source_path):
            source_type = "folder"
            status_msg = f"Analyzing folder: {os.path.basename(source_path)}"
            # Quick count of email files in folder
            try:
                email_files = [f for f in os.listdir(source_path) 
                             if f.lower().endswith(('.txt', '.mbox'))]
                status_msg += f" ({len(email_files)} email files found)"
            except:
                pass
        else:
            messagebox.showerror("Invalid Path", 
                               "The selected path is neither a file nor a folder")
            return
        
        
        # Prepare the results display area
        self.batch_results_text.config(state=tk.NORMAL)    # Enable editing temporarily
        self.batch_results_text.delete(1.0, tk.END)        # Clear previous results
        
        # Show processing message
        self.batch_results_text.insert(tk.END, f"{status_msg}\n")
        if source_type == "folder":
            self.batch_results_text.insert(tk.END, "Scanning folder and processing all email files...\n\n")
        else:
            self.batch_results_text.insert(tk.END, "Processing email file...\n\n")
        self.root.update()  # Update UI to show the message
        
        try:
            # Use simplified detector engine for batch processing
            batch_results = self.detector.analyze_batch_emails(source_path)
            
            # Check if there was an error
            if 'error' in batch_results:
                self.batch_results_text.delete(1.0, tk.END)
                self.batch_results_text.insert(tk.END, f"Error: {batch_results['error']}\n")
                return
            
            # Format batch results for display
            formatted_results = {'results': [], 'summary': None}
            
            # Format each individual result
            for result in batch_results['results']:
                formatted_result = self.results_display.format_batch_analysis_results(
                    result['email_record'], result['total_score'], result['rule_hits'], 
                    self.detector.config, result['email_number']
                )
                formatted_result['email_data']['sender'] = result['email_record'].from_addr
                formatted_result['email_data']['subject'] = result['email_record'].subject
                formatted_result['email_data']['filename'] = result.get('filename', 'Unknown')
                formatted_results['results'].append(formatted_result)
            
            # Use the existing summary
            formatted_results['summary'] = batch_results['summary']
            
            # Store results for saving
            self.current_batch_results = formatted_results
            
            # Display formatted results
            self.results_display.display_batch_results(formatted_results)
            
        except Exception as e:
            # Handle any unexpected errors
            self.batch_results_text.delete(1.0, tk.END)
            self.batch_results_text.insert(tk.END, f"Error: {str(e)}\n")
            messagebox.showerror("Analysis Error", f"Error analyzing batch: {str(e)}")
    
    
    def save_batch_results(self):
        # Check if there are results to save
        if not self.current_batch_results:
            messagebox.showwarning("No Data", "Please analyze a batch of emails first")
            return
        
        # Show file save popup
        output_file = filedialog.asksaveasfilename(
            title="Save Batch Analysis Results",
            defaultextension=".txt",               # Default to .txt extension
            filetypes=[
                ("Text files", "*.txt"),           # Primary option
            ]
        )
        
        # If user selected a location (didn't cancel)
        if output_file:
            try:
                # Get all text from the results display area
                results_text = self.batch_results_text.get(1.0, tk.END)
                
                # Write the results to the selected file
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(results_text)
                
                # Show success message with file location
                messagebox.showinfo("Results Saved", 
                                  f"Batch analysis results saved!\n\nLocation: {output_file}")
                
            except Exception as e:
                # Show error if file saving fails
                messagebox.showerror("Save Error", f"Error saving file: {str(e)}")
    
    def clear_batch(self):
        # Clear the file selection field
        self.file_path_var.set("")
        
        # Clear the results display area
        self.batch_results_text.config(state=tk.NORMAL)    # Enable editing temporarily
        self.batch_results_text.delete(1.0, tk.END)        # Delete all results text
        self.batch_results_text.config(state=tk.DISABLED)  # Disable editing again
        
        # Clear stored results
        self.current_batch_results = None
    


# Application Startup
def main():
    try:
        # Create the main tkinter window
        root = tk.Tk()
        
        # Create the PhishGuard GUI application instance
        app = PhishingDetectorGUI(root)
        
        # Start the GUI event loop (keeps window open and responsive)
        root.mainloop()
        
    except Exception as e:
        
        try:
            # Show error message
            messagebox.showerror("Startup Error", f"{str(e)}")
        except:
            pass


if __name__ == "__main__":
    main()