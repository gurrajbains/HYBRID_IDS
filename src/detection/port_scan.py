import time

# A port scan enumerates through different ports looking for an opening in any program running on said port

class PortScanDetector:
    def __init__(self, port_threshold=10, time_window=10):
        self.port_threshold = port_threshold
        self.time_window = time_window
        self.connection_history = {}

    def check(self, src_ip, dst_ip, dst_port):
        current_time = time.time()

        if src_ip not in self.connection_history:
            self.connection_history[src_ip] = []

        self.connection_history[src_ip].append((current_time, dst_ip, dst_port))

        recent_connections = []

        # Cleanup for connection attempts older than the configured time window
        for timestamp, destination_ip, destination_port in self.connection_history[src_ip]:
            if current_time - timestamp <= self.time_window:
                recent_connections.append((timestamp, destination_ip, destination_port))

        self.connection_history[src_ip] = recent_connections

        unique_ports = set()

        for _, _, destination_port in recent_connections:
            unique_ports.add(destination_port)

        if len(unique_ports) >= self.port_threshold:
            return True

        return False


