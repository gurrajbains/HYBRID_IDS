import json
from pathlib import Path

from src.alerts.alert_manager import create_alert


DEFAULT_EVE_PATH = Path("logs/suricata/eve.json")


def convert_severity(severity):
    severity_map = {
        1: "HIGH",
        2: "MEDIUM",
        3: "LOW"
    }

    return severity_map.get(severity, "UNKNOWN")


def normalize_suricata_alert(event):
    alert_data = event.get("alert", {})

    return {
        "timestamp": event.get("timestamp"),
        "alert_type": alert_data.get("signature", "Unknown Suricata Alert"),
        "severity": convert_severity(alert_data.get("severity")),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dst_ip": event.get("dest_ip"),
        "dst_port": event.get("dest_port"),
        "protocol": event.get("proto"),
        "signature_id": alert_data.get("signature_id"),
        "category": alert_data.get("category"),
        "action": alert_data.get("action")
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


def build_description(alert):
    src_port = alert.get("src_port")
    dst_port = alert.get("dst_port")
    signature_id = alert.get("signature_id")
    category = alert.get("category")
    action = alert.get("action")

    return (
        f"Suricata signature {signature_id} detected traffic "
        f"from {alert['src_ip']}:{src_port} to "
        f"{alert['dst_ip']}:{dst_port}. "
        f"Category: {category or 'Unknown'}. "
        f"Action: {action or 'Unknown'}."
    )


def import_suricata_alerts(eve_path=DEFAULT_EVE_PATH):
    alerts = read_suricata_alerts(eve_path)
    imported_alerts = []

    for alert in alerts:
        logged_alert = create_alert(
            alert_type=alert["alert_type"],
            severity=alert["severity"],
            src_ip=alert["src_ip"],
            dst_ip=alert["dst_ip"],
            description=build_description(alert),
            detector="Suricata",
            protocol=alert["protocol"],
            timestamp=alert["timestamp"]
        )

        imported_alerts.append(logged_alert)

    return imported_alerts


def print_suricata_summary(alerts):
    print(f"Suricata alerts: {len(alerts)}")

    for alert in alerts[:10]:
        print(
            f"[{alert['timestamp']}] "
            f"{alert['alert_type']} | "
            f"{alert['src_ip']}:{alert['src_port']} -> "
            f"{alert['dst_ip']}:{alert['dst_port']} | "
            f"{alert['protocol']} | "
            f"{alert['severity']}"
        )


if __name__ == "__main__":
    suricata_alerts = read_suricata_alerts()
    print_suricata_summary(suricata_alerts)