import time
from collections import defaultdict


class PortScanDetector:
    def __init__(self, threshold=10, window=10, cooldown=15):
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown

        self.attempts = defaultdict(list)
        self.last_alert = {}

    def check(self, src_ip, dst_ip, dst_port, current_time=None):
        if current_time is None:
            current_time = time.time()

        key = (src_ip, dst_ip)

        self.attempts[key].append(
            (current_time, dst_port)
        )

        cutoff = current_time - self.window

        self.attempts[key] = [
            (timestamp, port)
            for timestamp, port in self.attempts[key]
            if timestamp >= cutoff
        ]

        unique_ports = {
            port
            for _, port in self.attempts[key]
        }

        if len(unique_ports) < self.threshold:
            return False

        last_alert_time = self.last_alert.get(key)

        if last_alert_time is not None:
            if current_time - last_alert_time < self.cooldown:
                return False

        self.last_alert[key] = current_time

        return True