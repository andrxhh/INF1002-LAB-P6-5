"""
PhishGuard CLI and GUI Entry Points

This module provides command-line interface for PhishGuard phishing detection system.
It supports both CLI-based batch processing and GUI mode for interactive analysis.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from phishguard.config import load_config
from phishguard.scoring import evaluate_email
from phishguard.ingestion.loaders import iterate_emails
from phishguard.normalize.parse_mime import parse_email_to_record
from phishguard.reporting.writers import write_results


def main():
    """Main entry point for PhishGuard CLI/GUI"""
    parser = argparse.ArgumentParser(
        description="PhishGuard - Rule-based phishing email detection system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  phishguard --gui                    # Launch graphical interface
  phishguard emails/                  # Process emails in directory
  phishguard email.eml               # Process single email file
  phishguard --config custom.json emails/  # Use custom config
        """
    )
    
    parser.add_argument(
        "source",
        nargs="?",
        help="Email file or directory to analyze (not needed for GUI mode)"
    )
    
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch graphical user interface"
    )
    
    parser.add_argument(
        "--config",
        type=str,
        help="Path to configuration file"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        help="Output file for results (JSON format)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Launch GUI if requested
    if args.gui:
        launch_gui()
        return
    
    # Validate CLI arguments
    if not args.source:
        parser.error("Email source is required unless using --gui mode")
    
    # Load configuration
    config = load_config(args.config)
    
    # Process emails
    try:
        process_emails_cli(args.source, config, args.output, args.verbose)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def launch_gui():
    """Launch the PhishGuard GUI application"""
    try:
        # Import GUI components
        import tkinter as tk
        from phishguard.app.ui import PhishingDetectorGUI
        
        print("🚀 Starting PhishGuard GUI...")
        
        # Create and run GUI
        root = tk.Tk()
        app = PhishingDetectorGUI(root)
        
        print("✅ GUI initialized successfully")
        print("📱 Application ready for use")
        
        root.mainloop()
        
    except ImportError as e:
        print(f"❌ GUI dependencies not available: {e}", file=sys.stderr)
        print("Install tkinter or run in CLI mode", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Failed to start GUI: {e}", file=sys.stderr)
        sys.exit(1)


def process_emails_cli(source: str, config: dict, output_file: Optional[str] = None, verbose: bool = False):
    """Process emails in CLI mode"""
    source_path = Path(source)
    
    if not source_path.exists():
        raise FileNotFoundError(f"Source not found: {source}")
    
    results = []
    processed_count = 0
    error_count = 0
    
    print(f"📧 Processing emails from: {source}")
    
    # Process emails
    for email_path, email_msg in iterate_emails(source_path):
        try:
            # Convert to EmailRecord
            email_record = parse_email_to_record(email_msg)
            
            # Analyze email
            total_score, rule_hits = evaluate_email(email_record, config)
            
            # Determine classification
            thresholds = config.get('thresholds', {})
            safe_max = thresholds.get('safe_max', 2.0)
            phishing_min = thresholds.get('phishing_min', 2.0)
            
            if total_score <= safe_max:
                classification = "SAFE"
            elif total_score >= phishing_min:
                classification = "PHISHING"
            else:
                classification = "SUSPICIOUS"
            
            # Store result
            result = {
                'file_path': str(email_path),
                'from_addr': email_record.from_addr,
                'subject': email_record.subject,
                'classification': classification,
                'total_score': total_score,
                'rule_hits': [
                    {
                        'rule_name': hit.rule_name,
                        'passed': hit.passed,
                        'score_delta': hit.score_delta,
                        'severity': hit.severity.name,
                        'details': hit.details
                    }
                    for hit in rule_hits
                ]
            }
            
            results.append(result)
            processed_count += 1
            
            # Print progress
            if verbose or classification in ['PHISHING', 'SUSPICIOUS']:
                print(f"📁 {email_path.name}: {classification} (score: {total_score:.2f})")
            
        except Exception as e:
            error_count += 1
            if verbose:
                print(f"❌ Error processing {email_path}: {e}")
            continue
    
    # Print summary
    print(f"\n📊 Processing complete:")
    print(f"   ✅ Processed: {processed_count} emails")
    print(f"   ❌ Errors: {error_count} emails")
    
    if results:
        safe_count = len([r for r in results if r['classification'] == 'SAFE'])
        suspicious_count = len([r for r in results if r['classification'] == 'SUSPICIOUS'])
        phishing_count = len([r for r in results if r['classification'] == 'PHISHING'])
        
        print(f"   🟢 Safe: {safe_count}")
        print(f"   🟡 Suspicious: {suspicious_count}")
        print(f"   🔴 Phishing: {phishing_count}")
        
        # Save results if output file specified
        if output_file:
            write_results(results, output_file)
            print(f"   💾 Results saved to: {output_file}")


if __name__ == "__main__":
    main()
