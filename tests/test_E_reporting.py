import sys
import json 
import csv
from pathlib import Path

# Set up paths to ensure the src directory is importable
ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
sys.path.insert(0, str(SRC_DIR))

from phishguard.reporting import writers

# Sample data to be used in tests
sample = [
    {
        "file_path": "emails/test1.eml",
        "from_addr": "phisher@fake.com",
        "subject": "Win a prize!",
        "classification": "phishing",
        "total_score": 20,
        "rule_hits": [
            {"rule_name": "Suspicious Link", "passed": False},
            {"rule_name": "Urgent Language", "passed": True},
        ],
    }
]

# Permanent output folder for test results
output_dir = Path(__file__).parent / "output"
output_dir.mkdir(exist_ok=True)

def test_json():
    """Test writing results in JSON format and validate output."""
    output_file = output_dir / "sample_results.json"
    json_results = writers.write_results(sample, str(output_file), format="json")

    assert json_results  # Ensure function returns a truthy value
    assert output_file.exists()  # Ensure file was created

    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert data["metadata"]["total_emails"] == 1  # Check metadata correctness

def test_writecsv():
    """Test writing results in CSV format and validate output."""
    output_file = output_dir / "sample.csv"
    csv_results = writers.write_results(sample, str(output_file), format="csv")

    assert csv_results  # Ensure function returns a truthy value
    assert output_file.exists()  # Ensure file was created

    rows = list(csv.DictReader(output_file.open(encoding="utf-8")))
    assert len(rows) == 1  # Only one sample row should be present
    assert rows[0]["classification"] == "phishing"  # Check field value

def test_auto_detect_format():
    """Ensure auto format detection works for both JSON and CSV."""
    json_file = output_dir / "auto_results.json"
    csv_file = output_dir / "auto_results.csv"

    assert writers.write_results(sample, str(json_file), format="auto")
    assert writers.write_results(sample, str(csv_file), format="auto")

    assert json_file.exists()  # JSON file should be created
    assert csv_file.exists()   # CSV file should be created

if __name__ == "__main__":
    # Run all tests if script is executed directly
    test_json()
    test_writecsv()
    test_auto_detect_format()
    print("All tests passed!")
