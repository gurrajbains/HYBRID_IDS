import json
import os


METRICS_PATH = "logs/metrics.json"


class MetricsTracker:
    def __init__(self):
        self.total_packets = 0

        self.protocol_counts = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "OTHER": 0
        }

        self.total_alerts = 0
        self.alert_counts = {}

    def record_packet(self, protocol):
        self.total_packets += 1

        if protocol not in self.protocol_counts:
            protocol = "OTHER"

        self.protocol_counts[protocol] += 1

        self.save_metrics()

    def record_alert(self, alert_type):
        self.total_alerts += 1

        if alert_type not in self.alert_counts:
            self.alert_counts[alert_type] = 0

        self.alert_counts[alert_type] += 1

        self.save_metrics()

    def get_metrics(self):
        return {
            "total_packets": self.total_packets,
            "protocol_counts": self.protocol_counts,
            "total_alerts": self.total_alerts,
            "alert_counts": self.alert_counts
        }

    def save_metrics(self):
        os.makedirs("logs", exist_ok=True)

        with open(METRICS_PATH, "w", encoding="utf-8") as metrics_file:
            json.dump(
                self.get_metrics(),
                metrics_file,
                indent=4
            )