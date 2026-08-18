from datetime import datetime


def create_alert(alert_type, severity, src_ip, dst_ip, description):
    alert = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": alert_type,
        "severity": severity,
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "description": description
    }

    print("\n[ALERT]")
    print(f"Time: {alert['timestamp']}")
    print(f"Type: {alert['type']}")
    print(f"Severity: {alert['severity']}")
    print(f"Source IP: {alert['source_ip']}")
    print(f"Destination IP: {alert['destination_ip']}")
    print(f"Description: {alert['description']}\n")

    return alert