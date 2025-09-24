#!/usr/bin/env python3
#====================================
#          Imports                  =
#====================================
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import filedialog
import os
import sys
from pathlib import Path

#====================================
#          Project Root            =
#====================================
project_root = Path(__file__).parent.parent.parent.parent
src_path = project_root / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

#====================================
#          Imports                  =
#====================================
try:
    from phishguard.app.detector_engine import PhishingDetector
    from phishguard.app.results_display import ResultsDisplayManager
# help us catch import errors
except ImportError as e:
    messagebox.showerror("Import Error", str(e))
    sys.exit(1)
    
        #====================================
        #          GUI Class               =
        #====================================
class PhishingDetectorGUI:
    
    def __init__(self, root):
        self.root = root
        
        try:
            self.detector = PhishingDetector()
# help us catch startup errors
        except Exception as e:
            messagebox.showerror("Startup Error", str(e))
            sys.exit(1)
        
        self.current_batch_results = None
        
        #====================================
        #        Setup UI (main window)     =
        #==================================== 
        self.setup_ui()
    #top window title and size
    def setup_ui(self):
        self.root.title("PhishGuard - Email Detection System")
        self.root.geometry("1000x800")
        self.root.configure(bg='#f0f0f0')
        #icons logo
        try:
            icon_photo = tk.PhotoImage(file='gui icon.png') #icon TBC to be added
            self.root.iconphoto(False, icon_photo) 
        except Exception as e:
            pass
        
        # GUI style/theme
        style = ttk.Style() 
        style.theme_use('classic')
        
        #main frame
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 20))
        header_frame.columnconfigure(1, weight=1)
        
        #logo
        try:
            self.logo_photo = tk.PhotoImage(file='App Logo.png')
            logo_width = self.logo_photo.width()
            logo_height = self.logo_photo.height()
            if logo_width > 80 or logo_height > 80:
                scale_factor = min(80/logo_width, 80/logo_height)
                new_width = int(logo_width * scale_factor)
                new_height = int(logo_height * scale_factor)
                self.logo_photo = self.logo_photo.subsample(int(1/scale_factor))
            
            logo_label = ttk.Label(header_frame, image=self.logo_photo)
            logo_label.grid(row=0, column=0, rowspan=2, sticky=tk.W, padx=(0, 15))
        except Exception as e:
            logo_label = ttk.Label(header_frame, text="[LOGO]", font=('Arial', 12, 'bold'))
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
        notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
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
        input_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        input_frame.columnconfigure(1, weight=1)  # Make input fields expandable
        
        # Sender Email section
        ttk.Label(input_frame, text="Sender Email:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.sender_entry = ttk.Entry(input_frame, width=60, font=('Arial', 10))  # Text input for sender
        self.sender_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        
        # Subject Line section
        ttk.Label(input_frame, text="Subject:", font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.subject_entry = ttk.Entry(input_frame, width=60, font=('Arial', 10))  # Text input for subject
        self.subject_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        
        # Email Body Input Section
        ttk.Label(input_frame, text="Email Body:", font=('Arial', 10, 'bold')).grid(row=2, column=0, sticky=(tk.W, tk.N), pady=5)
        self.body_text = scrolledtext.ScrolledText(input_frame, width=70, height=10,   # Large text area with scrollbar
                                                  wrap=tk.WORD, font=('Arial', 10))
        self.body_text.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=5)
        
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
        results_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(15, 0))
        results_frame.columnconfigure(0, weight=1)  # Make results area expandable
        results_frame.rowconfigure(0, weight=1)     # Make results area expandable vertically
        
        # Scrollable text widget
        self.results_text = scrolledtext.ScrolledText(results_frame, width=90, height=20, 
                                                     wrap=tk.WORD, state=tk.DISABLED, font=('Arial', 10))
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Resizing fix for results area
        self.individual_frame.rowconfigure(2, weight=1)
    
    def setup_batch_tab(self):
        # Configure the main tab to expand the second column (file path field)
        self.batch_frame.columnconfigure(1, weight=1)
        
        # File Selection Section
        # =============================
        # Frames for file selection
        file_frame = ttk.LabelFrame(self.batch_frame, text="File Selection", padding="15")
        file_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        file_frame.columnconfigure(1, weight=1)  # Make file path field expandable
        
        # File Path Input and Browse Button
        ttk.Label(file_frame, text="Email File:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.file_path_var = tk.StringVar()  # Variable to store selected file path
        self.file_path_entry = ttk.Entry(file_frame, textvariable=self.file_path_var,   # Display selected file path
                                        width=60, state='readonly', font=('Arial', 10))  # Read-only (user can't type)
        self.file_path_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 10), pady=5)
        
        # Browse Button - to open files for uploading
        browse_btn = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        browse_btn.grid(row=0, column=2, pady=5)
        
        # supported file formats for uploading
        instructions = ttk.Label(file_frame, 
                                text="Supported Formats:\n"
                                     "• Text files (.txt) - Plain text or email format\n"
                                     "• Unix Mailbox (.mbox) - Standard Unix mbox format",
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
        batch_results_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(15, 0))
        batch_results_frame.columnconfigure(0, weight=1)  # Make results area expandable
        batch_results_frame.rowconfigure(0, weight=1)     # Make results area expandable vertically
        
        # Scrollable text widget
        self.batch_results_text = scrolledtext.ScrolledText(batch_results_frame, width=90, height=20, 
                                                           wrap=tk.WORD, state=tk.DISABLED, font=('Arial', 10))
        self.batch_results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Initialize results display manager
        self.results_display = ResultsDisplayManager(self.results_text, self.batch_results_text)
        
        # Resizing fix for results area
        self.batch_frame.rowconfigure(2, weight=1)
    
    # ====================================
    # Individual Analysis Functions      =
    # ====================================
    
    def analyze_email(self):
        """Main function to analyze a single email for phishing threats"""
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
            # Send email data to the detection engine
            results = self.detector.analyze_email(sender, subject, body)
            
            # Display the formatted results
            self.results_display.display_individual_results(results, sender, subject, body)
            
        except Exception as e:
            # Show error message if analysis fails
            messagebox.showerror("Analysis Error", f"Error analyzing email: {str(e)}")
    
    
    def clear_fields(self):
        """Reset all input fields and results area"""
        # Clear all input fields
        self.sender_entry.delete(0, tk.END)         # Clear sender field
        self.subject_entry.delete(0, tk.END)        # Clear subject field
        self.body_text.delete(1.0, tk.END)          # Clear body text area
        
        # Clear results display area
        self.results_text.config(state=tk.NORMAL)   # Enable editing temporarily
        self.results_text.delete(1.0, tk.END)       # Delete all results text
        self.results_text.config(state=tk.DISABLED) # Disable editing again
    
    def load_sample_email(self):
        """Load a sample phishing email for testing purposes"""
        # First clear all existing content
        self.clear_fields()
        
        # Sample phishing email data - when button is clicked this is the email that will be loaded
        sample_sender = "security@paypaI.com"
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
    
    def browse_file(self):
        """Open file dialog to select email file for batch processing"""
        # Show file selection dialog with supported file types
        file_path = filedialog.askopenfilename(
            title="Select Email File for Batch Analysis",
            filetypes=[
                ("Text files", "*.txt"),        # Plain text files
                ("Unix Mailbox", "*.mbox")      # Unix mailbox format
            ]
        )
        
        # If user selected a file (didn't cancel)
        if file_path:
            # Store the selected file path
            self.file_path_var.set(file_path)
            
            # File path is now displayed in the readonly text field
    
    def analyze_batch(self):
        """Process multiple emails from a file and analyze each for phishing"""
        # Get the selected file path from the file selection field
        file_path = self.file_path_var.get().strip()
        
        # Validate that a file has been selected
        if not file_path:
            messagebox.showwarning("File Required", "Please select an email file for batch analysis")
            return
        
        # Prepare the results display area
        self.batch_results_text.config(state=tk.NORMAL)    # Enable editing temporarily
        self.batch_results_text.delete(1.0, tk.END)        # Clear previous results
        
        try:
            # Send file to detection engine
            batch_results = self.detector.analyze_batch_emails(file_path)
            
            # Check if there was an error
            if 'error' in batch_results:
                self.batch_results_text.delete(1.0, tk.END)
                self.batch_results_text.insert(tk.END, f"Error: {batch_results['error']}\n")
                return
            
            # Store results for saving
            self.current_batch_results = batch_results
            
            # Display formatted results
            self.results_display.display_batch_results(batch_results)
            
        except Exception as e:
            # Handle any unexpected errors
            self.batch_results_text.delete(1.0, tk.END)
            self.batch_results_text.insert(tk.END, {str(e)}\n)
            messagebox.showerror("Analysis Error", {str(e)})
    
    
    def save_batch_results(self):
        """Export batch analysis results to a text file"""
        # Check if there are results to save
        if not self.current_batch_results:
            messagebox.showwarning("No Data", "Please analyze a batch of emails first")
            return
        
        # Show file save dialog
        output_file = filedialog.asksaveasfilename(
            title="Save Batch Analysis Results",
            defaultextension=".txt",               # Default to .txt extension
            filetypes=[
                ("Text files", "*.txt"),           # Primary option
                ("All files", "*.*")               # Allow other formats
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
                messagebox.showerror("Save Error", f"Error saving results: {str(e)}")
    
    def clear_batch(self):
        """Reset the batch analysis area"""
        # Clear the file selection
        self.file_path_var.set("")
        
        # Clear the results display area
        self.batch_results_text.config(state=tk.NORMAL)    # Enable editing temporarily
        self.batch_results_text.delete(1.0, tk.END)        # Delete all results text
        self.batch_results_text.config(state=tk.DISABLED)  # Disable editing again
        
        # Clear stored results
        self.current_batch_results = None
    


# ====================================
# APPLICATION STARTUP
# ====================================

def main():
    """Main function to start the PhishGuard GUI application"""
    try:
        # Create the main tkinter window
        root = tk.Tk()
        
        # Create the PhishGuard GUI application instance
        app = PhishingDetectorGUI(root)
        
        # Start the GUI event loop (keeps window open and responsive)
        root.mainloop()
        
    except Exception as e:
        # Handle any startup errors gracefully
        try:
            # Show error dialog to user
            messagebox.showerror("Startup Error", 
                               f"PhishGuard failed to start:\n\n{str(e)}\n\n"
                               f"Please check that all required files are present.")
        except:
            # If even the error dialog fails, just exit silently
            pass


# ====================================
# PROGRAM ENTRY POINT
# ====================================
if __name__ == "__main__":
    # Only run main() if this file is executed directly (not imported)
    main()