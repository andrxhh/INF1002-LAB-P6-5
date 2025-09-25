

import argparse, json, os
from pathlib import Path
from typing import Dict, List, Tuple

import sys


from phishguard.config import load_config
from phishguard.rules import *
from phishguard.pipeline.evaluate import *
from phishguard.reporting import *
from phishguard.ingestion.loaders import *
from phishguard.normalize.parse_mime import *
from phishguard.features.extractors import *
from phishguard.schema import EmailRecord
from phishguard.scoring import *
from phishguard.reporting.writers import *

# def load_config_json(path: str | None) -> Dict:
#     if not path:
#         return {}
#     with open(path, "r", encoding="utf-8") as f:
#         return json.load(f)


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

    


def main():
    ap = argparse.ArgumentParser("phishguard")
    ap.add_argument("--eml", help="Path to a single .eml or raw email")
    ap.add_argument("--record-json", help="Path to an EmailRecord JSON")
    ap.add_argument("--folder", help="Evaluate all .eml/raw files under this folder")


    ap.add_argument("--out-json", help="Write a JSON result file (single input) to this path")
    ap.add_argument("--out-csv", help="Write a CSV file (batch) to this path")
    ap.add_argument("--gui", help ="# Launch graphical interface")
    args = ap.parse_args()

    print(ap)

    
    CFG = load_config()

    # Single raw/.eml or mbox or folder → unified evaluate_source
    if args.eml:
        results = evaluate_email_file(args.eml, RULES, CFG)
        file_id, score, label, hits = results[0]

        # print(results)
        payload = result_to_json(Path(file_id).name, score, label, hits)
        if args.out_json:
            write_json_results(payload, args.out_json)
        else:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    if args.record_json:
        with open(args.record_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        rec = EmailRecord(**data)
    
        score, label, hits = evaluate_email_file(rec, RULES, CFG)
        payload = result_to_json(Path(args.record_json).name, score, label, hits)
        if args.out_json:
            write_json_results(payload, args.out_json)
        else:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    if args.folder:
        results = evaluate_source(args.folder, RULES, CFG)
        header = ["id", "label", "score", "rule_name", "score_delta", "severity", "details_json"]
        rows = results_to_csv_rows(results)
        out = args.out_csv or "results.csv"
        write_csv_file(out, header, rows)
        print(f"Wrote {out} with {len(rows)} rows.")
        return
    
    if args.gui:
        launch_gui()
        return

    
if __name__ == "__main__":
    main()