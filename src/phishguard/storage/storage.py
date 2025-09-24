import sys
import csv
import os
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path
from phishguard.ingestion.loaders import iterate_emails
from phishguard.normalize.parse_mime import normalize_header, decode_address, extract_body

#The following class will be used to store the email results for Phisguard e.g "sender", "subject", "body" ...."
class EmailReportManager: 

    def _init_(self, csv_filename: str = "emailReport.csv"):
        #Target CSV path and create a schema for the state CSV
        self.csv_filename = csv_filename

        self.fieldnames = ['fromEmail', 'Subject', 'Body', 'threatLevel', 'timestamp']

        #Create the CSV file with headers if it doesn't exist
        self._ensure_csv_exists()
    
    def _ensure_csv_exists(self): 
        if not os.path.exists(self.csv_filename):
            with open(self.csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
                writer.writeheader()
            print(f"Created new CSV file: {self.csv_filename}")
    
    #Addition of emailRecords of email records to the CSV file
    def add_email_record(self, from_email: str, subject: str, body: str, threat_level: str) -> bool:
        try:
            valid_threat_levels = ['Low', 'Medium', 'High', 'Critical']
            if threat_level not in valid_threat_levels:
                print(f"Invalid threat level: {threat_level}. Must be one of: {valid_threat_levels}")
                return False
            
            #To keep the CSV clean and readable
            truncated_body = body[:200] + "..." if len(body) > 200 else body  

            #Create the record
            record = {
                'fromEmail': from_email,
                'Subject': subject,
                'Body': truncated_body,
                'threatLevel': threat_level,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            #Append the record into the CSV file
            with open(self.csv_filename, 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
                writer.writerow(record)
        
            print(f"Added email record: {from_email} - {threat_level} threat")
            return True
        
        except Exception as e:
            print(f"Error adding email record: {str(e)}")
            return False
    
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
        return [record for record in all_records if record['threatLevel'] == threat_level]
    
    ''' 
    def get_statistics(self) -> Dict[str, int]:
        records = self.read_all_records()
        stats = {'Total': len(records)}
        threat_levels = ['Low', 'Medium', 'High', 'Critical']
        for level in threat_levels:
            stats[level] = len([r for r in records if r['threatLevel'] == level])
        return stats
    '''

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
            print(f"  From: {record['fromEmail']}")
            print(f"  Subject: {record['Subject']}")
            print(f"  Body: {record['Body']}")
            print(f"  Threat Level: {record['threatLevel']}")
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
            # Normalize headers and addresses
            headers = normalize_header(email_msg)
            subject = headers.get('subject', '')
            _from_display, from_addr, _reply_to = decode_address(email_msg)

            # Extract body text (prefer text/plain, fallback to HTML converted to text)
            body_text, _body_html = extract_body(email_msg)

            # Store normalized fields into CSV; default threat level 'Low' here
            if manager.add_email_record(from_addr, subject, body_text or '', 'Low'):
                added_count += 1
    except Exception as e:
        print(f"Failed while processing emails: {e}")

    print(f"Added {added_count} normalized email(s) to {manager.csv_filename}")


if __name__ == "__main__":
    main()