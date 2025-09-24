import sys
import csv
import os
import json
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from phishguard.ingestion.loaders import iterate_emails
from phishguard.normalize.parse_mime import normalize_header, decode_address, extract_body
from phishguard.schema.classes import EmailRecord, RuleHit, Severity

#The following class will be used to store the email results for Phisguard e.g "sender", "subject", "body" ...."
class EmailReportManager:

    def __init__(self, csv_filename: str = "emailReport.csv"):
        # Target CSV path and define CSV schema
        self.csv_filename = csv_filename
        # If no directory provided, place file under ./outPutResult/
        if not os.path.isabs(self.csv_filename) and os.path.dirname(self.csv_filename) == '':
            output_dir = os.path.join(os.getcwd(), 'outPutResult')
            os.makedirs(output_dir, exist_ok=True)
            # Create a new unique filename per run using current date/time
            self.run_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_name, ext = os.path.splitext(self.csv_filename)
            if not ext:
                ext = '.csv'
            stamped = f"{base_name}_{self.run_timestamp}{ext}"
            self.csv_filename = os.path.join(output_dir, stamped)
        else:
            # If a directory/path was provided, still ensure uniqueness by stamping
            dir_part = os.path.dirname(self.csv_filename)
            base_name = os.path.basename(self.csv_filename)
            name, ext = os.path.splitext(base_name)
            if not ext:
                ext = '.csv'
            self.run_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.csv_filename = os.path.join(dir_part or os.getcwd(), f"{name}_{self.run_timestamp}{ext}")

        # Derive JSON alongside stamped CSV file
        base, _ext = os.path.splitext(self.csv_filename)
        self.json_filename = f"{base}.json"

        # CSV JSON fields
        self.fieldnames = [
            'header',
            'from_addr',
            'reply_to_addr',
            'Subject',
            'body_Text',
            'body_HTML',
            'URL',
            'URL_Display_Pairs',
            'Attachments',
            'rulenames',
            'description',
            'severity',
            'timestamp',
        ]

        # Create the CSV file with headers if non existent
        self._ensure_csv_exists()
        # Create the JSON file if non existent
        self._ensure_json_exists()
    
    def _ensure_csv_exists(self): 
        # Ensure parent directory exists
        parent_dir = os.path.dirname(self.csv_filename)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
        if not os.path.exists(self.csv_filename):
            with open(self.csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
                writer.writeheader()
            print(f"Created new CSV file: {self.csv_filename}")

    def _ensure_json_exists(self):
        parent_dir = os.path.dirname(self.json_filename)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
        if not os.path.exists(self.json_filename):
            with open(self.json_filename, 'w', encoding='utf-8') as jf:
                json.dump([], jf, ensure_ascii=False, indent=2)
            print(f"Created new JSON file: {self.json_filename}")
    
    # Add email records 
    def add_email_record(self, *args, **kwargs) -> bool:
        try:
            if args and isinstance(args[0], EmailRecord):
                email: EmailRecord = args[0]
                rule_hits: List[RuleHit] = []
                if len(args) > 1 and isinstance(args[1], list):
                    rule_hits = args[1]
                record = self._serialize_email_record(email, rule_hits)
            else:
                # Legacy positional: (from_addr, subject, body_text, threat_level)
                if len(args) == 4 and not kwargs:
                    record = self._serialize_primitives(
                        headers={},
                        from_addr=args[0],
                        reply_to_addr='',
                        subject=args[1],
                        body_text=args[2],
                        body_html='',
                        urls=[],
                        url_display_pairs=[],
                        attachments=[],
                        rule_hits=[],
                        severity_hint=args[3],
                    )
                else:
                    record = self._serialize_primitives(
                        headers=kwargs.get('headers', {}),
                        from_addr=kwargs.get('from_addr', ''),
                        reply_to_addr=kwargs.get('reply_to_addr', ''),
                        subject=kwargs.get('Subject') or kwargs.get('subject', ''),
                        body_text=kwargs.get('body_Text') or kwargs.get('body_text', ''),
                        body_html=kwargs.get('body_HTML') or kwargs.get('body_html', ''),
                        urls=kwargs.get('URL') or kwargs.get('urls', []) or [],
                        url_display_pairs=kwargs.get('URL_Display_Pairs') or kwargs.get('url_display_pairs', []) or [],
                        attachments=kwargs.get('Attachments') or kwargs.get('attachments', []) or [],
                        rule_hits=kwargs.get('rule_hits', []) or [],
                        severity_hint=kwargs.get('severity', ''),
                    )

            # Append the record into the CSV file and JSON file
            with open(self.csv_filename, 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
                writer.writerow(record)

            print(f"Added email record: {record.get('from_addr','')} - severity={record.get('severity','')}")
            self._append_json_record(record)
            return True

        except Exception as e:
            print(f"Error adding email record: {str(e)}")
            return False

    def _append_json_record(self, record: Dict[str, str]) -> None:
        try:
            # Read existing list, append, write back
            items: List[Dict[str, str]]
            if os.path.exists(self.json_filename):
                with open(self.json_filename, 'r', encoding='utf-8') as jf:
                    try:
                        items = json.load(jf)
                        if not isinstance(items, list):
                            items = []
                    except json.JSONDecodeError:
                        items = []
            else:
                items = []
            items.append(record)
            with open(self.json_filename, 'w', encoding='utf-8') as jf:
                json.dump(items, jf, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Warning: failed to append to JSON file '{self.json_filename}': {e}")
    
    def _serialize_email_record(self, email: 'EmailRecord', rule_hits: List['RuleHit']) -> Dict[str, str]:
        # Determine overall severity as the highest RuleHit severity (if any)
        severity_value = ''
        if rule_hits:
            try:
                highest = max((h.severity for h in rule_hits), key=lambda s: s.value)
                severity_value = highest.name.title()
            except Exception:
                severity_value = ''
        headers_str = json.dumps(email.headers, ensure_ascii=False)
        urls_str = '|'.join(email.urls)
        url_pairs_str = '|'.join([f"{disp}->{url}" for disp, url in email.url_display_pairs])
        attachments_str = '|'.join(email.attachments)
        rule_names = '|'.join([h.rule_name for h in rule_hits])
        descriptions = json.dumps([h.details for h in rule_hits], ensure_ascii=False)
        return {
            'header': headers_str,
            'from_addr': email.from_addr,
            'reply_to_addr': email.reply_to_addr or '',
            'Subject': email.subject,
            'body_Text': email.body_text,
            'body_HTML': email.body_html or '',
            'URL': urls_str,
            'URL_Display_Pairs': url_pairs_str,
            'Attachments': attachments_str,
            'rulenames': rule_names,
            'description': descriptions,
            'severity': severity_value,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }

    def _serialize_primitives(
        self,
        *,
        headers: Dict[str, str],
        from_addr: str,
        reply_to_addr: str,
        subject: str,
        body_text: str,
        body_html: str,
        urls: List[str],
        url_display_pairs: List[Tuple[str, str]],
        attachments: List[str],
        rule_hits: List['RuleHit'],
        severity_hint: str,
    ) -> Dict[str, str]:
        # Build a minimal EmailRecord and optional RuleHit list
        try:
            from phishguard.schema.classes import EmailRecord as ER, RuleHit as RH, Severity as Sev
        except Exception:
            ER = EmailRecord; RH = RuleHit; Sev = None
        email = ER(
            from_display='',
            from_addr=from_addr,
            reply_to_addr=reply_to_addr or None,
            subject=subject,
            body_text=body_text,
            body_html=body_html or None,
            urls=list(urls or []),
            url_display_pairs=list(url_display_pairs or []),
            attachments=list(attachments or []),
            headers=dict(headers or {}),
            spf_pass=None,
            dkim_pass=None,
            dmarc_pass=None,
        )
        rh_list: List['RuleHit'] = list(rule_hits or [])
        if not rh_list and severity_hint:
            sev = None
            try:
                sev = Sev[str(severity_hint).strip().upper()] if Sev else None
            except Exception:
                sev = None
            if sev is not None:
                rh_list = [RH(rule_name='manual', passed=False, score_delta=0.0, severity=sev, details={})]
        return self._serialize_email_record(email, rh_list)
    
    def add_multiple_records(self, records: List[Dict[str, str]]) -> int:
        success_count = 0
        for record in records:
            if self.add_email_record(
                record.get('fromEmail', ''),
                record.get('Subject', ''),
                record.get('Body', ''),
                record.get('threatLevel', 'Low')
            ):
                success_count += 1
        return success_count
    
    def read_all_records(self) -> List[Dict[str, str]]: #for potential future use
        records = []
        try:
            with open(self.csv_filename, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                records = list(reader)
        except Exception as e:
            print(f"Error reading CSV file: {str(e)}")
        return records
    
    #Filtering data by threat level 
    def get_records_by_threat_level(self, threat_level: str) -> List[Dict[str, str]]:
        all_records = self.read_all_records()
        return [record for record in all_records if record.get('classification') == threat_level]

    def showThreatAmt(self, threat_level: str) -> int:
        """
        Display the current amount of emails with the given classification e.g Low, Medium, High, Critical
        """
        records = self.read_all_records()
        count = sum(1 for r in records if r.get('classification') == threat_level)
        print(f"Total {threat_level} emails: {count}")
        return count


    def display_records(self, limit: Optional[int] = None):
        records = self.read_all_records()
        if limit:
            records = records[:limit]

        if not records:
            print("No records found in CSV file.")
            return

        print(f"\n{'='*80}")
        print(f"EMAIL REPORT - {len(records)} records")
        print(f"{'='*80}")

        for i, record in enumerate(records, 1):
            print(f"\nRecord {i}:")
            print(f"  File Path: {record.get('file_path','')}")
            print(f"  From: {record.get('from_addr','')}")
            print(f"  Subject: {record.get('subject','')}")
            print(f"  Classification: {record.get('classification','')}")
            print(f"  Total Score: {record.get('total_score','')}")
            print(f"  Rule Hits: {record.get('rule_hits_count','')}")
            print(f"  Failed Rules: {record.get('failed_rules','')}")
            print(f"  Timestamp: {record['timestamp']}")
            print("-" * 40)
    
def main():
    print("Email Report Manager")
    print("=" * 30)

    # Expect a source path (file, mbox, or directory) to read emails from
    if len(sys.argv) < 2:
        print("Usage: python storage.py <path-to-email-file-or-directory>")
        return

    source_path = sys.argv[1]
    path_obj = Path(source_path)
    if not path_obj.exists():
        print(f"Path not found: {source_path}")
        return

    manager = EmailReportManager()

    added_count = 0
    print("\nNormalizing and storing emails...")
    try:
        for _path, email_msg in iterate_emails(source_path):

            headers = normalize_header(email_msg)
            subject = headers.get('subject', '')
            _from_display, from_addr, _reply_to = decode_address(email_msg)

            # Extract body text 
            body_text, _body_html = extract_body(email_msg)

            # Store normalized fields into CSV with new schema; placeholder scoring
            if manager.add_email_record(
                file_path=str(_path),
                from_addr=from_addr,
                subject=subject,
                classification='Low',
                total_score=0,
                rule_hits_count=0,
                failed_rules='',
            ):
                added_count += 1
    except Exception as e:
        print(f"Failed while processing emails: {e}")

    print(f"Added {added_count} normalized email(s) to {manager.csv_filename}")

    # Show total by classification
    for level in ['Low', 'Medium', 'High', 'Critical']:
        manager.showThreatAmt(level)


if __name__ == "__main__":
    main()