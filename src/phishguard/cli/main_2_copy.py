"""
PhishGuard CLI and GUI Entry Points - Enhanced Copy

This module provides command-line interface for PhishGuard phishing detection system.
It supports both CLI-based batch processing and GUI mode for interactive analysis.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from phishguard.config import load_config
from phishguard.rules import RULES
from phishguard.pipeline.evaluate import evaluate_email_file, build_email_record
from phishguard.ingestion.loaders import iterate_emails
from phishguard.schema import EmailRecord
from phishguard.scoring.aggregate import evaluate_email
from phishguard.reporting.writers import write_json_results, write_csv_results, write_results


def result_to_json(filename: str, score: float, label: str, hits: List) -> Dict:
    """Convert analysis results to JSON format"""
    return {
        "filename": filename,
        "score": score,
        "classification": label,
        "rule_hits": [
            {
                "rule_name": hit.rule_name,
                "passed": hit.passed,
                "score_delta": hit.score_delta,
                "severity": hit.severity.name,
                "details": hit.details
            } for hit in hits
        ]
    }


def results_to_csv_rows(results: List[Tuple]) -> List[List]:
    """Convert results to CSV row format"""
    rows = []
    for file_id, score, label, hits in results:
        for hit in hits:
            row = [file_id, label, score, hit.rule_name, hit.score_delta, hit.severity.name, json.dumps(hit.details)]
            rows.append(row)
    return rows


def evaluate_source(folder_path: str, rules, config) -> List[Tuple]:
    """Evaluate all emails in a folder"""
    return evaluate_email_file(Path(folder_path), rules, config)


def launch_gui():
    """Launch the PhishGuard GUI application"""
    try:
        # Import GUI components
        import tkinter as tk
        from phishguard.app.ui import PhishingDetectorGUI
        
        # Create and run GUI
        root = tk.Tk()
        app = PhishingDetectorGUI(root)
        root.mainloop()
        
    except ImportError as e:
        print(f"GUI dependencies not available: {e}", file=sys.stderr)
        print("Install tkinter or run in CLI mode", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Failed to start GUI: {e}", file=sys.stderr)
        sys.exit(1)


def process_emails_cli(source: str, config: dict, output_file: Optional[str] = None, verbose: bool = False):
    """Process emails in CLI mode"""
    source_path = Path(source)
    
    if not source_path.exists():
        raise FileNotFoundError(f"Source not found: {source}")
    
    results = []
    processed_count = 0
    error_count = 0
    
    if verbose:
        print(f"Processing emails from: {source}")
    
    # Process emails
    for email_path, email_msg in iterate_emails(source_path):
        try:
            # Convert to EmailRecord
            email_record = build_email_record(email_msg)
            
            # Analyze email
            rule_hits, total_score, classification = evaluate_email(email_record, RULES, config)
            
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
                print(f"{email_path.name}: {classification} (score: {total_score:.2f})")
            
        except Exception as e:
            error_count += 1
            if verbose:
                print(f"Error processing {email_path}: {e}")
            continue
    
    # Print summary
    if verbose or processed_count > 0:
        print(f"Processing complete:")
        print(f"  Processed: {processed_count} emails")
        if error_count > 0:
            print(f"  Errors: {error_count} emails")
    
    if results:
        safe_count = len([r for r in results if r['classification'].upper() in ['SAFE', 'Safe']])
        suspicious_count = len([r for r in results if r['classification'].upper() in ['SUSPICIOUS', 'Unknown']])
        phishing_count = len([r for r in results if r['classification'].upper() in ['PHISHING', 'Phishing']])
        
        if verbose:
            print(f"  Safe: {safe_count}")
            print(f"  Suspicious: {suspicious_count}")
            print(f"  Phishing: {phishing_count}")
        
        # Save results if output file specified
        if output_file:
            write_results(results, output_file)
            if verbose:
                print(f"  Results saved to: {output_file}")
    
    return results


def main():
    """Main entry point for PhishGuard CLI/GUI"""
    parser = argparse.ArgumentParser(
        description="PhishGuard - Rule-based phishing email detection system"
    )
    
    parser.add_argument("--eml", help="Path to a single .eml or raw email")
    parser.add_argument("--record-json", help="Path to an EmailRecord JSON")
    parser.add_argument("--folder", help="Evaluate all .eml/raw files under this folder")
    parser.add_argument("--out-json", help="Write a JSON result file (single input) to this path")
    parser.add_argument("--out-csv", help="Write a CSV file (batch) to this path")
    parser.add_argument("--gui", action="store_true", help="Launch graphical interface")
    parser.add_argument("--config", type=str, help="Path to configuration file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Launch GUI if requested
    if args.gui:
        launch_gui()
        return
    
    # Load configuration
    CFG = load_config(args.config) if args.config else load_config()
    
    # Single email file processing
    if args.eml:
        try:
            results = evaluate_email_file(Path(args.eml), RULES, CFG)
            if results:
                file_id, score, label, hits = results[0]
                payload = result_to_json(Path(file_id).name, score, label, hits)
                
                if args.out_json:
                    write_json_results([payload], Path(args.out_json))
                    if args.verbose:
                        print(f"Results saved to: {args.out_json}")
                else:
                    print(json.dumps(payload, ensure_ascii=False, indent=2))
            else:
                print("No results found for the email file")
        except Exception as e:
            print(f"Error processing email file: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # EmailRecord JSON processing
    if args.record_json:
        try:
            with open(args.record_json, "r", encoding="utf-8") as f:
                data = json.load(f)
            rec = EmailRecord(**data)
        
            # Use evaluate_email directly on the EmailRecord
            hits, score, label = evaluate_email(rec, RULES, CFG)
            payload = result_to_json(Path(args.record_json).name, score, label, hits)
            
            if args.out_json:
                write_json_results([payload], Path(args.out_json))
                if args.verbose:
                    print(f"Results saved to: {args.out_json}")
            else:
                print(json.dumps(payload, ensure_ascii=False, indent=2))
        except Exception as e:
            print(f"Error processing EmailRecord JSON: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # Folder batch processing
    if args.folder:
        try:
            results = process_emails_cli(args.folder, CFG, args.out_csv, args.verbose)
        except Exception as e:
            print(f"Error processing folder: {e}", file=sys.stderr)
            sys.exit(1)
        return
    
    # If no arguments provided, show help
    parser.print_help()


if __name__ == "__main__":
    main()