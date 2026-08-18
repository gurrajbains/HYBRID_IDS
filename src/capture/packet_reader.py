from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from src.detection.port_scan import PortScanDetector
port_scan_detector = PortScanDetector()
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
                print(f"[ALERT] Possible port scan detected from {src_ip}")
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