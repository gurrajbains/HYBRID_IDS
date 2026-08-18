import time


class IcmpFloodDetector:
    def __init__(self, icmp_threshold=25, time_window=10):
        self.icmp_threshold = icmp_threshold
        self.time_window = time_window
        self.icmp_history = {}

    def check(self, src_ip, dst_ip):
        current_time = time.time()
        key = (src_ip, dst_ip)

        if key not in self.icmp_history:
            self.icmp_history[key] = []

        self.icmp_history[key].append(current_time)

        recent_packets = []

        for timestamp in self.icmp_history[key]:
            if current_time - timestamp <= self.time_window:
                recent_packets.append(timestamp)

        self.icmp_history[key] = recent_packets

        if len(recent_packets) >= self.icmp_threshold:
            return True

        return False