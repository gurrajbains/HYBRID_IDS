import time
import statistics
from scapy.all import IP, TCP, UDP


class FlowTracker:
    def __init__(self, flow_timeout=15):
        self.flow_timeout = flow_timeout
        self.flows = {}

    def get_flow_key(self, packet):
        if IP not in packet:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        else:
            return None

        endpoint_one = (src_ip, src_port)
        endpoint_two = (dst_ip, dst_port)

        if endpoint_one <= endpoint_two:
            return endpoint_one, endpoint_two, protocol

        return endpoint_two, endpoint_one, protocol

    def create_flow(self, packet):
        current_time = time.time()

        if TCP in packet:
            origin_port = packet[TCP].sport
            destination_port = packet[TCP].dport
        else:
            origin_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        return {
            "start_time": current_time,
            "last_time": current_time,

            "origin_ip": packet[IP].src,
            "origin_port": origin_port,
            "destination_ip": packet[IP].dst,
            "destination_port": destination_port,

            "forward_packets": 0,
            "backward_packets": 0,

            "forward_bytes": 0,
            "backward_bytes": 0,

            "forward_lengths": [],
            "backward_lengths": [],
            "packet_lengths": [],

            "packet_times": [],
            "forward_times": [],
            "backward_times": [],

            "syn_count": 0,
            "ack_count": 0,
            "fin_count": 0,
            "rst_count": 0,
            "psh_count": 0,
            "urg_count": 0
        }

    def update_flow(self, packet):
        key = self.get_flow_key(packet)

        if key is None:
            return None

        if key not in self.flows:
            self.flows[key] = self.create_flow(packet)

        flow = self.flows[key]

        current_time = time.time()
        packet_size = len(packet)

        flow["last_time"] = current_time
        flow["packet_lengths"].append(packet_size)
        flow["packet_times"].append(current_time)

        src_ip = packet[IP].src

        if TCP in packet:
            src_port = packet[TCP].sport
        else:
            src_port = packet[UDP].sport

        is_forward = src_ip == flow["origin_ip"] and src_port == flow["origin_port"]

        if is_forward:
            flow["forward_packets"] += 1
            flow["forward_bytes"] += packet_size
            flow["forward_lengths"].append(packet_size)
            flow["forward_times"].append(current_time)

        else:
            flow["backward_packets"] += 1
            flow["backward_bytes"] += packet_size
            flow["backward_lengths"].append(packet_size)
            flow["backward_times"].append(current_time)

        if TCP in packet:
            flags = str(packet[TCP].flags)

            if "S" in flags:
                flow["syn_count"] += 1

            if "A" in flags:
                flow["ack_count"] += 1

            if "F" in flags:
                flow["fin_count"] += 1

            if "R" in flags:
                flow["rst_count"] += 1

            if "P" in flags:
                flow["psh_count"] += 1

            if "U" in flags:
                flow["urg_count"] += 1

        return flow

    def calculate_stats(self, values):
        if not values:
            return 0, 0, 0, 0

        minimum = min(values)
        maximum = max(values)
        mean = statistics.mean(values)

        if len(values) > 1:
            std = statistics.pstdev(values)
        else:
            std = 0

        return minimum, maximum, mean, std

    def calculate_iat(self, timestamps):
        if len(timestamps) < 2:
            return 0, 0, 0, 0

        iats = []

        for index in range(1, len(timestamps)):
            iats.append(timestamps[index] - timestamps[index - 1])

        minimum = min(iats)
        maximum = max(iats)
        mean = statistics.mean(iats)

        if len(iats) > 1:
            std = statistics.pstdev(iats)
        else:
            std = 0

        return minimum, maximum, mean, std

    def extract_features(self, flow):
        duration = flow["last_time"] - flow["start_time"]

        if duration <= 0:
            duration = 0.000001

        total_packets = flow["forward_packets"] + flow["backward_packets"]
        total_bytes = flow["forward_bytes"] + flow["backward_bytes"]

        packet_min, packet_max, packet_mean, packet_std = self.calculate_stats(flow["packet_lengths"])
        fwd_min, fwd_max, fwd_mean, fwd_std = self.calculate_stats(flow["forward_lengths"])
        bwd_min, bwd_max, bwd_mean, bwd_std = self.calculate_stats(flow["backward_lengths"])

        flow_iat_min, flow_iat_max, flow_iat_mean, flow_iat_std = self.calculate_iat(flow["packet_times"])
        fwd_iat_min, fwd_iat_max, fwd_iat_mean, fwd_iat_std = self.calculate_iat(flow["forward_times"])
        bwd_iat_min, bwd_iat_max, bwd_iat_mean, bwd_iat_std = self.calculate_iat(flow["backward_times"])

        packet_variance = packet_std ** 2

        return {
            "Destination Port": flow["destination_port"],

            "Flow Duration": duration,

            "Total Fwd Packets": flow["forward_packets"],
            "Total Backward Packets": flow["backward_packets"],

            "Total Length of Fwd Packets": flow["forward_bytes"],
            "Total Length of Bwd Packets": flow["backward_bytes"],

            "Fwd Packet Length Max": fwd_max,
            "Fwd Packet Length Min": fwd_min,
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": fwd_std,

            "Bwd Packet Length Max": bwd_max,
            "Bwd Packet Length Min": bwd_min,
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std": bwd_std,

            "Flow Bytes/s": total_bytes / duration,
            "Flow Packets/s": total_packets / duration,

            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,

            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,

            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,

            "Fwd Packets/s": flow["forward_packets"] / duration,
            "Bwd Packets/s": flow["backward_packets"] / duration,

            "Min Packet Length": packet_min,
            "Max Packet Length": packet_max,
            "Packet Length Mean": packet_mean,
            "Packet Length Std": packet_std,
            "Packet Length Variance": packet_variance,

            "FIN Flag Count": flow["fin_count"],
            "SYN Flag Count": flow["syn_count"],
            "RST Flag Count": flow["rst_count"],
            "PSH Flag Count": flow["psh_count"],
            "ACK Flag Count": flow["ack_count"],
            "URG Flag Count": flow["urg_count"]
        }

    def get_completed_flows(self):
        current_time = time.time()
        completed = []

        for key, flow in list(self.flows.items()):
            if current_time - flow["last_time"] >= self.flow_timeout:
                completed.append(self.extract_features(flow))
                del self.flows[key]

        return completed

    def flush_flows(self):
        completed = []

        for key, flow in list(self.flows.items()):
            completed.append(self.extract_features(flow))
            del self.flows[key]

        return completed