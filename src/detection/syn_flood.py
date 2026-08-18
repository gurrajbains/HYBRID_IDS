import time


class SynFloodDetector:
    def __init__(self, syn_threshold=50, time_window=10):
        self.syn_threshold = syn_threshold
        self.time_window = time_window
        self.syn_history = {}

    def check(self, src_ip, dst_ip):
        current_time = time.time()
        key = (src_ip, dst_ip)

        if key not in self.syn_history:
            self.syn_history[key] = []

        self.syn_history[key].append(current_time)

        recent_syns = []

        for timestamp in self.syn_history[key]:
            if current_time - timestamp <= self.time_window:
                recent_syns.append(timestamp)

        self.syn_history[key] = recent_syns

        if len(recent_syns) >= self.syn_threshold:
            return True

        return False
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from src.detection.port_scan import PortScanDetector
from src.alerts.alert_manager import create_alert
from src.detection.syn_flood import SynFloodDetector
port_scan_detector = PortScanDetector()
syn_flood_detector = SynFloodDetector()
def process_packet(packet):

    if IP not in packet:
        return
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    packet_size = len(packet)

    protocol = "OTHER"
    src_port = None
    dst_port = None
    flags = None

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = str(packet[TCP].flags)
        if flags == "S":
            if port_scan_detector.check(src_ip, dst_ip, dst_port):
                create_alert(
                    "Port Scan",
                    "Medium",
                    src_ip,
                    dst_ip,
                    f"Source contacted at least {port_scan_detector.port_threshold} unique ports within {port_scan_detector.time_window} seconds"
                )
            if syn_flood_detector.check(src_ip, dst_ip):
                create_alert(
                    "SYN Flood",
                    "High",
                    src_ip,
                    dst_ip,
                    f"Source sent at least {syn_flood_detector.syn_threshold} SYN packets within {syn_flood_detector.time_window} seconds"
                )
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        

    elif ICMP in packet:
        protocol = "ICMP"
        #src_port = packet[ICMP].sport
        #dst_port = packet[ICMP].dport
        #flags = str(packet[ICMP].flags)
    print(
        f"[{timestamp}] "
        f"{protocol} | "
        f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
        f"Size: {packet_size} bytes | "
        f"Flags: {flags}"
    )

def capture_packets():
    print("Initiating capture processing with IDS")
    print("Ctrl + C to stop process")
    sniff(iface="Realtek USB GbE Family Controller", prn=process_packet, store=False) 

if __name__ == "__main__":
    capture_packets()
if __name__ == "__main__":
    detector = SynFloodDetector(syn_threshold=5, time_window=10)

    test_ip = "192.168.1.50"
    target_ip = "192.168.1.19"

    for attempt in range(1, 6):
        detected = detector.check(test_ip, target_ip)
        print(f"SYN attempt {attempt} -> Alert: {detected}")