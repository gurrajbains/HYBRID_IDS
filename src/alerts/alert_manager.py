import json
import os
from datetime import datetime


LOG_FILE = "logs/alerts.jsonl"


def create_alert(alert_type, severity, src_ip, dst_ip, description, detector=None, protocol=None):
    alert = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": alert_type,
        "severity": severity,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "description": description,
        "detector": detector,
        "protocol": protocol
    }

    print("\n[ALERT]")
    print(f"Time: {alert['timestamp']}")
    print(f"Type: {alert['type']}")
    print(f"Severity: {alert['severity']}")
    print(f"Source IP: {alert['source_ip']}")
    print(f"Destination IP: {alert['destination_ip']}")
    print(f"Protocol: {alert['protocol']}")
    print(f"Detector: {alert['detector']}")
    print(f"Description: {alert['description']}\n")

    os.makedirs("logs", exist_ok=True)

    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(alert) + "\n")

    return alert