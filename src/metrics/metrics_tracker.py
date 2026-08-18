class MetricsTracker:
    def __init__(self):
        self.total_packets = 0
        self.protocol_counts = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "OTHER":0
        }

        self.total_alerts = 0
        self.alert_counts = {}

    def record_packet(self, protocol):
        self.total_packets += 1

        if protocol in self.protocol_counts:
            self.protocol_counts[protocol] += 1
        else:
            self.protocol_counts["OTHER"] += 1

    def record_alert(self, alert_type):
        self.total_alerts += 1

        if alert_type not in self.alert_counts:
            self.alert_counts[alert_type] = 0

        self.alert_counts[alert_type] += 1

    def get_metrics(self):
        return {
            "total_packets": self.total_packets,
            "protocol_counts": self.protocol_counts,
            "total_alerts": self.total_alerts,
            "alert_counts": self.alert_counts
        }