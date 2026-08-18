import time


class SSHBruteForceDetector:
    def __init__(self, attempt_threshold=10, time_window=30):
        self.attempt_threshold = attempt_threshold
        self.time_window = time_window
        self.attempt_history = {}

    def check(self, src_ip, dst_ip, dst_port):
        if dst_port != 22:
            return False

        current_time = time.time()
        key = (src_ip, dst_ip)

        if key not in self.attempt_history:
            self.attempt_history[key] = []

        self.attempt_history[key].append(current_time)

        recent_attempts = []

        for timestamp in self.attempt_history[key]:
            if current_time - timestamp <= self.time_window:
                recent_attempts.append(timestamp)

        self.attempt_history[key] = recent_attempts

        if len(recent_attempts) >= self.attempt_threshold:
            return True

        return False
if __name__ == "__main__":
    detector = SSHBruteForceDetector(attempt_threshold=5, time_window=30)

    test_ip = "192.168.1.50"
    target_ip = "192.168.1.19"

    for attempt in range(1, 6):
        detected = detector.check(test_ip, target_ip, 22)
        print(f"SSH attempt {attempt} -> Alert: {detected}")