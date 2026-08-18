import time
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

        return {
            "start_time": current_time,
            "last_time": current_time,

            "origin_ip": packet[IP].src,
            "origin_port": packet[TCP].sport if TCP in packet else packet[UDP].sport,

            "forward_packets": 0,
            "backward_packets": 0,

            "forward_bytes": 0,
            "backward_bytes": 0,

            "packet_lengths": [],

            "syn_count": 0,
            "ack_count": 0,
            "fin_count": 0,
            "rst_count": 0
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

        src_ip = packet[IP].src

        if TCP in packet:
            src_port = packet[TCP].sport
        else:
            src_port = packet[UDP].sport

        if src_ip == flow["origin_ip"] and src_port == flow["origin_port"]:
            flow["forward_packets"] += 1
            flow["forward_bytes"] += packet_size

        else:
            flow["backward_packets"] += 1
            flow["backward_bytes"] += packet_size

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

        return flow

    def get_completed_flows(self):
        current_time = time.time()
        completed = []

        for key, flow in list(self.flows.items()):
            if current_time - flow["last_time"] >= self.flow_timeout:
                features = self.extract_features(flow)
                completed.append(features)

                del self.flows[key]

        return completed

    def extract_features(self, flow):
        duration = flow["last_time"] - flow["start_time"]

        if duration <= 0:
            duration = 0.000001

        total_packets = flow["forward_packets"] + flow["backward_packets"]
        total_bytes = flow["forward_bytes"] + flow["backward_bytes"]

        if flow["packet_lengths"]:
            minimum_length = min(flow["packet_lengths"])
            maximum_length = max(flow["packet_lengths"])
            average_length = sum(flow["packet_lengths"]) / len(flow["packet_lengths"])
        else:
            minimum_length = 0
            maximum_length = 0
            average_length = 0

        return {
            "Flow Duration": duration,
            "Total Fwd Packets": flow["forward_packets"],
            "Total Backward Packets": flow["backward_packets"],
            "Total Length of Fwd Packets": flow["forward_bytes"],
            "Total Length of Bwd Packets": flow["backward_bytes"],
            "Flow Bytes/s": total_bytes / duration,
            "Flow Packets/s": total_packets / duration,
            "Min Packet Length": minimum_length,
            "Max Packet Length": maximum_length,
            "Packet Length Mean": average_length,
            "FIN Flag Count": flow["fin_count"],
            "SYN Flag Count": flow["syn_count"],
            "RST Flag Count": flow["rst_count"],
            "ACK Flag Count": flow["ack_count"]
        }
    def flush_flows(self):
        completed = []

        for key, flow in list(self.flows.items()):
            features = self.extract_features(flow)
            completed.append(features)

            del self.flows[key]

        return completed