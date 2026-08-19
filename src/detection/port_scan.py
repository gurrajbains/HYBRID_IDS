import time


class PortScanDetector:
    def __init__(self, port_threshold=10, time_window=10, cooldown=15):
        self.port_threshold = port_threshold
        self.time_window = time_window
        self.cooldown = cooldown

        self.history = {}
        self.last_alert = {}

    def check(self, src_ip, dst_ip, dst_port):
        current_time = time.time()

        if src_ip not in self.history:
            self.history[src_ip] = []

        self.history[src_ip].append((current_time, dst_ip, dst_port))

        self.history[src_ip] = [
            attempt
            for attempt in self.history[src_ip]
            if current_time - attempt[0] <= self.time_window
        ]

        unique_ports = {
            port
            for _, destination, port in self.history[src_ip]
            if destination == dst_ip
        }

        if len(unique_ports) < self.port_threshold:
            return False

        alert_key = (src_ip, dst_ip)

        last_alert_time = self.last_alert.get(alert_key)

        if last_alert_time is not None:
            if current_time - last_alert_time < self.cooldown:
                return False

        self.last_alert[alert_key] = current_time

        return True