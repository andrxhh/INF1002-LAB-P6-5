import sys
import json 
import csv
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
sys.path.insert(0, str(SRC_DIR))

from phishguard.reporting import writers

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

#permanent output folder
output_dir= Path(__file__).parent/ "output"
output_dir.mkdir(exist_ok=True)

def test_json():
    output_file= output_dir / "sample_results.json"
    json_results = writers.write_results(sample, str(output_file), format="json")

    assert json_results
    assert output_file.exists()

    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert data["metadata"]["total_emails"]==1

def test_writecsv():
    output_file = output_dir / "sample.csv"
    csv_results = writers.write_results(sample, str(output_file), format="csv")

    assert csv_results
    assert output_file.exists()

    rows = list(csv.DictReader(output_file.open(encoding="utf-8")))
    assert len(rows) == 1
    assert rows[0]["classification"] == "phishing"



def test_auto_detect_format():
    """Ensure auto format detection works"""
    json_file = output_dir / "auto_results.json"
    csv_file = output_dir / "auto_results.csv"

    assert writers.write_results(sample, str(json_file), format="auto")
    assert writers.write_results(sample, str(csv_file), format="auto")

    assert json_file.exists()
    assert csv_file.exists()


if __name__ == "__main__":
    test_json()
    test_writecsv()
    test_auto_detect_format()
    print("All tests passed!")
