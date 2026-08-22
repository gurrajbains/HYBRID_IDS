import json
from pathlib import Path


DEFAULT_EVE_PATH = Path("logs/suricata/eve.json")


def normalize_suricata_alert(event):
    alert_data = event.get("alert", {})

    return {
        "timestamp": event.get("timestamp"),
        "source": "Suricata",
        "alert_type": alert_data.get("signature", "Unknown Suricata Alert"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "protocol": event.get("proto"),
        "severity": alert_data.get("severity"),
        "signature_id": alert_data.get("signature_id"),
        "category": alert_data.get("category"),
        "action": alert_data.get("action"),
    }


def read_suricata_alerts(eve_path=DEFAULT_EVE_PATH):
    eve_path = Path(eve_path)
    alerts = []

    if not eve_path.exists():
        return alerts

    with eve_path.open("r", encoding="utf-8") as eve_file:
        for line in eve_file:
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            alerts.append(normalize_suricata_alert(event))

    return alerts


def print_suricata_summary(alerts):
    print(f"Suricata alerts: {len(alerts)}")

    for alert in alerts[:10]:
        print(
            f"[{alert['timestamp']}] "
            f"{alert['alert_type']} | "
            f"{alert['src_ip']}:{alert['src_port']} -> "
            f"{alert['dest_ip']}:{alert['dest_port']} | "
            f"{alert['protocol']} | "
            f"Severity {alert['severity']}"
        )


if __name__ == "__main__":
    suricata_alerts = read_suricata_alerts()
    print_suricata_summary(suricata_alerts)