from scapy.all import sniff, IP, TCP, UDP, ICMP, rdpcap
from datetime import datetime
from src.detection.port_scan import PortScanDetector
from src.alerts.alert_manager import create_alert
from src.detection.syn_flood import SynFloodDetector
from src.detection.icmp_flood import IcmpFloodDetector
from src.metrics.metrics_tracker import MetricsTracker
from src.detection.ssh_brute_force import SSHBruteForceDetector
from src.flow.flow_tracker import FlowTracker
import argparse


port_scan_detector = PortScanDetector()
syn_flood_detector = SynFloodDetector()
icmp_flood_detector = IcmpFloodDetector()
ssh_brute_force_detector = SSHBruteForceDetector()
metrics_tracker = MetricsTracker()
flow_tracker = FlowTracker()


def process_packet(packet):
    if IP not in packet:
        return
    flow_tracker.update_flow(packet)

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
                    f"Source contacted at least {port_scan_detector.port_threshold} unique ports within {port_scan_detector.time_window} seconds",
                    detector="PortScanDetector",
                    protocol="TCP"
                )

                metrics_tracker.record_alert("Port Scan")

            if syn_flood_detector.check(src_ip, dst_ip):
                create_alert(
                    "SYN Flood",
                    "High",
                    src_ip,
                    dst_ip,
                    f"Source sent at least {syn_flood_detector.syn_threshold} SYN packets within {syn_flood_detector.time_window} seconds",
                    detector="SynFloodDetector",
                    protocol="TCP"
                )

                metrics_tracker.record_alert("SYN Flood")

            if ssh_brute_force_detector.check(src_ip, dst_ip, dst_port):
                create_alert(
                    "SSH Brute Force",
                    "High",
                    src_ip,
                    dst_ip,
                    f"Source attempted at least {ssh_brute_force_detector.attempt_threshold} SSH connections within {ssh_brute_force_detector.time_window} seconds",
                    detector="SSHBruteForceDetector",
                    protocol="TCP"
                )

                metrics_tracker.record_alert("SSH Brute Force")
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

        if packet[ICMP].type == 8:
            if icmp_flood_detector.check(src_ip, dst_ip):
                create_alert(
                    "ICMP Flood",
                    "High",
                    src_ip,
                    dst_ip,
                    f"Source sent at least {icmp_flood_detector.icmp_threshold} ICMP Echo Requests within {icmp_flood_detector.time_window} seconds",
                    detector="IcmpFloodDetector",
                    protocol="ICMP"
                )

                metrics_tracker.record_alert("ICMP Flood")
    
    metrics_tracker.record_packet(protocol)
    process_completed_flows()
    print(
        f"[{timestamp}] "
        f"{protocol} | "
        f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
        f"Size: {packet_size} bytes | "
        f"Flags: {flags}"
    )
def process_completed_flows():
    completed_flows = flow_tracker.get_completed_flows()

    for flow in completed_flows:
        print("\n--- Completed Flow ---")

        for feature, value in flow.items():
            print(f"{feature}: {value}")

def print_metrics():
    metrics = metrics_tracker.get_metrics()

    print("\n--- IDS Metrics ---")
    print(f"Total Packets: {metrics['total_packets']}")
    print(f"TCP Packets: {metrics['protocol_counts']['TCP']}")
    print(f"UDP Packets: {metrics['protocol_counts']['UDP']}")
    print(f"ICMP Packets: {metrics['protocol_counts']['ICMP']}")
    print(f"Other Packets: {metrics['protocol_counts']['OTHER']}")
    print(f"Total Alerts: {metrics['total_alerts']}")

    if metrics["alert_counts"]:
        print("\nAlerts by Type:")

        for alert_type, count in metrics["alert_counts"].items():
            print(f"{alert_type}: {count}")


def capture_packets():
    print("Initiating capture processing with IDS")
    print("Ctrl + C to stop process")

    try:
        sniff(
            iface="Realtek USB GbE Family Controller",
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\nCapture stopped.")

    finally:
        flush_remaining_flows()
        print_metrics()


def analyze_pcap(file_path):
    print(f"Analyzing PCAP file: {file_path}")

    packets = rdpcap(file_path)

    for packet in packets:
        process_packet(packet)
    flush_remaining_flows()
    print_metrics()
    

def flush_remaining_flows():
    completed_flows = flow_tracker.flush_flows()

    for flow in completed_flows:
        print("\n--- Completed Flow ---")

        for feature, value in flow.items():
            print(f"{feature}: {value}")
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

