from scapy.all import sniff, IP, TCP, UDP, ICMP, rdpcap
from datetime import datetime
from src.detection.port_scan import PortScanDetector
from src.alerts.alert_manager import create_alert
from src.detection.syn_flood import SynFloodDetector
import argparse
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

def analyze_pcap(file_path):
    packets = rdpcap(file_path)
    for packet in packets:
        process_packet(packet)
def main():
    parser = argparse.ArgumentParser(description="Hybrid IDS packet analyzer")

    parser.add_argument("--live", action="store_true", help="Capture live network traffic")
    parser.add_argument("--pcap", type=str, help="Analyze a PCAP file")

    args = parser.parse_args()

    if args.live:
        capture_packets()

    elif args.pcap:
        analyze_pcap(args.pcap)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()