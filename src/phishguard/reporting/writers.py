# G: implement as provided earlier

import json
import csv
from typing import List , Dict

def write_json(results: List[Dict], filepath: str): 
    #writing results into a JSON File.
    try:
        with open(filepath,"w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
    
    except Exception as e:
        print(f"Error writing JSON: {e}")

def write_csv(results: List[Dict], filepath: str):
    #Writing the results to a CSV File.
    if not results:
        print("No results to write into the CSV")
        return
    
    try:
        headers = results[0].keys()
        with open(filepath, "w", newline="",encoding="utf-8") as f :
             writer = csv.DictWriter(f, fieldnames=headers)
             writer.writeheader()
             for row in results:
                writer.writerow(row)
    except:
        print(f"Error writing CSV.")
