import time


class SSHBruteForceDetector:
    def __init__(self, attempt_threshold=10, time_window=30, cooldown=30):
        self.attempt_threshold = attempt_threshold
        self.time_window = time_window
        self.cooldown = cooldown

        self.history = {}
        self.last_alert = {}

    def check(self, src_ip, dst_ip, dst_port):
        if dst_port != 22:
            return False

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

        if len(self.history[key]) < self.attempt_threshold:
            return False

        last_alert_time = self.last_alert.get(key)

        if last_alert_time is not None:
            if current_time - last_alert_time < self.cooldown:
                return False

        self.last_alert[key] = current_time

        return True