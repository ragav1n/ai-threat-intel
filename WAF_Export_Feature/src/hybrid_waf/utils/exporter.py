import csv
import json
from datetime import datetime

def export_to_csv(iocs, filename=None):
    filename = filename or f"export_iocs_{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=iocs[0].keys())
        writer.writeheader()
        writer.writerows(iocs)

def export_to_json(iocs, filename=None):
    filename = filename or f"export_iocs_{datetime.now().strftime('%Y%m%d%H%M%S')}.json"
    with open(filename, 'w', encoding='utf-8') as file:
        json.dump(iocs, file, indent=4)

def forward_to_siem(iocs):
    """
    Placeholder for integration with external SIEM or SOC tools like Splunk, ELK, etc.
    """
    print("Forwarding to SIEM (not implemented).")
