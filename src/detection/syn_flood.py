import time


class SynFloodDetector:
    def __init__(self, syn_threshold=50, time_window=10, cooldown=15):
        self.syn_threshold = syn_threshold
        self.time_window = time_window
        self.cooldown = cooldown

        self.history = {}
        self.last_alert = {}

    def check(self, src_ip, dst_ip):
        current_time = time.time()

        key = (src_ip, dst_ip)

        if key not in self.history:
            self.history[key] = []

        self.history[key].append(current_time)

        self.history[key] = [
            timestamp
            for timestamp in self.history[key]
            if current_time - timestamp <= self.time_window
        ]

        if len(self.history[key]) < self.syn_threshold:
            return False

        last_alert_time = self.last_alert.get(key)

        if last_alert_time is not None:
            if current_time - last_alert_time < self.cooldown:
                return False

        self.last_alert[key] = current_time

        return True