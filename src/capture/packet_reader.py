import argparse
import json
import os
from datetime import datetime

from scapy.all import ICMP, IP, TCP, UDP, rdpcap, sniff
from src.suricata.eve_reader import build_description
from src.suricata.runner import run_suricata_pcap
from src.alerts.alert_manager import create_alert as log_alert
from src.detection.icmp_flood import IcmpFloodDetector
from src.detection.port_scan import PortScanDetector
from src.detection.ssh_brute_force import SSHBruteForceDetector
from src.detection.syn_flood import SynFloodDetector
from src.flow.flow_tracker import FlowTracker
from src.metrics.metrics_tracker import MetricsTracker
from src.ml.live_detector import LiveMLDetector


INTERFACE_NAME = "Realtek USB GbE Family Controller"

FLOW_LOG_PATH = "logs/flows.jsonl"
PREDICTION_LOG_PATH = "logs/ml_predictions.jsonl"


metrics_tracker = MetricsTracker()
flow_tracker = FlowTracker()
live_ml_detector = LiveMLDetector()

port_scan_detector = PortScanDetector()
syn_flood_detector = SynFloodDetector()
ssh_brute_force_detector = SSHBruteForceDetector()
icmp_flood_detector = IcmpFloodDetector()


def append_jsonl(file_path, record):
    os.makedirs("logs", exist_ok=True)

    with open(file_path, "a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(record) + "\n")


def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def raise_alert(alert_type, severity, src_ip, dst_ip, description, detector, protocol, timestamp=None):
    alert = log_alert(
        alert_type,
        severity,
        src_ip,
        dst_ip,
        description,
        detector,
        protocol,
        timestamp
    )

    metrics_tracker.record_alert(alert_type)

    return alert


def log_flow(flow):
    flow_end_time = flow.get("Flow End Time")

    if flow_end_time is not None:
        timestamp = format_timestamp(flow_end_time)
    else:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    record = {
        "timestamp": timestamp,
        "source_ip": flow.get("Source IP"),
        "source_port": flow.get("Source Port"),
        "destination_ip": flow.get("Destination IP"),
        "destination_port": flow.get("Destination Port"),
        "protocol": flow.get("Protocol"),
        "packet_count": flow.get("Packet Count", 0),
        "total_bytes": flow.get("Total Bytes", 0),
        "duration_microseconds": flow.get("Flow Duration", 0)
    }

    append_jsonl(FLOW_LOG_PATH, record)


def log_prediction(flow, result):
    flow_end_time = flow.get("Flow End Time")

    if flow_end_time is not None:
        timestamp = format_timestamp(flow_end_time)
    else:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    record = {
        "timestamp": timestamp,
        "source_ip": flow.get("Source IP"),
        "source_port": flow.get("Source Port"),
        "destination_ip": flow.get("Destination IP"),
        "destination_port": flow.get("Destination Port"),
        "protocol": flow.get("Protocol"),
        "prediction": result["prediction"],
        "confidence": result["confidence"]
    }

    append_jsonl(PREDICTION_LOG_PATH, record)


def process_ml_result(flow, result):
    prediction = result["prediction"]
    confidence = result["confidence"]

    print("\n--- Completed Flow ---")
    print(f"ML Prediction: {prediction}")
    print(f"Confidence: {confidence:.2%}")

    log_prediction(flow, result)

    if prediction != "BENIGN":
        flow_end_time = flow.get("Flow End Time")

        if flow_end_time is not None:
            alert_timestamp = format_timestamp(flow_end_time)
        else:
            alert_timestamp = None

        raise_alert(
            "ML Detection",
            "High",
            flow.get("Source IP", "Unknown"),
            flow.get("Destination IP", "Unknown"),
            f"Random Forest classified flow as {prediction} with {confidence:.2%} confidence",
            "RandomForestLiveDetector",
            flow.get("Protocol", "FLOW"),
            alert_timestamp
        )


def process_completed_flows(current_time):
    completed_flows = flow_tracker.get_completed_flows(current_time)

    if not completed_flows:
        metrics_tracker.set_active_flows(flow_tracker.get_active_flow_count())
        return

    for flow in completed_flows:
        metrics_tracker.record_flow()
        log_flow(flow)

        result = live_ml_detector.predict(flow)

        metrics_tracker.record_classification()
        process_ml_result(flow, result)

    metrics_tracker.set_active_flows(flow_tracker.get_active_flow_count())


def flush_remaining_flows():
    completed_flows = flow_tracker.flush_flows()

    if not completed_flows:
        metrics_tracker.set_active_flows(0)
        return

    print(f"\nClassifying {len(completed_flows)} remaining flows...")

    for flow in completed_flows:
        metrics_tracker.record_flow()
        log_flow(flow)

    results = live_ml_detector.predict_batch(completed_flows)

    for flow, result in zip(completed_flows, results):
        metrics_tracker.record_classification()
        process_ml_result(flow, result)

    metrics_tracker.set_active_flows(0)


def process_packet(packet):
    protocol = "OTHER"
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    flags = None

    packet_time = float(packet.time)
    packet_timestamp = format_timestamp(packet_time)

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    metrics_tracker.record_packet(protocol)

    print(
        f"[{packet_timestamp}] {protocol} | "
        f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
        f"Size: {len(packet)} bytes | Flags: {flags}"
    )

    if IP not in packet:
        return

    if TCP in packet:
        is_syn = bool(packet[TCP].flags & 0x02)
        is_ack = bool(packet[TCP].flags & 0x10)

        if is_syn and not is_ack:
            if port_scan_detector.check(src_ip, dst_ip, dst_port, packet_time):
                raise_alert(
                    "Port Scan",
                    "Medium",
                    src_ip,
                    dst_ip,
                    "Source contacted at least 10 unique ports within 10 seconds",
                    "PortScanDetector",
                    "TCP",
                    packet_timestamp
                )

            if syn_flood_detector.check(src_ip, dst_ip, packet_time):
                raise_alert(
                    "SYN Flood",
                    "High",
                    src_ip,
                    dst_ip,
                    "Source sent at least 50 SYN packets within 10 seconds",
                    "SynFloodDetector",
                    "TCP",
                    packet_timestamp
                )

            if ssh_brute_force_detector.check(src_ip, dst_ip, dst_port, packet_time):
                raise_alert(
                    "SSH Brute Force",
                    "High",
                    src_ip,
                    dst_ip,
                    "Source attempted at least 10 SSH connections within 30 seconds",
                    "SSHBruteForceDetector",
                    "TCP",
                    packet_timestamp
                )

    if ICMP in packet and packet[ICMP].type == 8:
        if icmp_flood_detector.check(src_ip, dst_ip, packet_time):
            raise_alert(
                "ICMP Flood",
                "High",
                src_ip,
                dst_ip,
                "Source sent at least 50 ICMP Echo Requests within 10 seconds",
                "IcmpFloodDetector",
                "ICMP",
                packet_timestamp
            )

    if TCP in packet or UDP in packet:
        flow_tracker.update_flow(packet, packet_time)
        metrics_tracker.set_active_flows(flow_tracker.get_active_flow_count())

    process_completed_flows(packet_time)


def print_metrics():
    metrics = metrics_tracker.get_metrics()

    print("\n--- IDS Metrics ---")
    print(f"Total Packets: {metrics['total_packets']}")
    print(f"TCP Packets: {metrics['protocol_counts']['TCP']}")
    print(f"UDP Packets: {metrics['protocol_counts']['UDP']}")
    print(f"ICMP Packets: {metrics['protocol_counts']['ICMP']}")
    print(f"Other Packets: {metrics['protocol_counts']['OTHER']}")
    print(f"Total Alerts: {metrics['total_alerts']}")
    print(f"Flows Analyzed: {metrics['flows_analyzed']}")
    print(f"Flows Classified: {metrics['flows_classified']}")
    print(f"Active Flows: {metrics['active_flows']}")

    if metrics["alert_counts"]:
        print("\nAlerts by Type:")

        for alert_type, count in metrics["alert_counts"].items():
            print(f"{alert_type}: {count}")
def process_suricata_results(file_path):
    print("\nRunning Suricata signature analysis...")

    suricata_alerts = run_suricata_pcap(file_path)

    for alert in suricata_alerts:
         raise_alert(
            alert["alert_type"],
            alert["severity"].title(),
            alert.get("src_ip") or "Unknown",
            alert.get("dst_ip") or "Unknown",
            build_description(alert),
            "Suricata",
            alert.get("protocol") or "Unknown",
            alert.get("timestamp")
        )

    print(f"Suricata alerts added to unified IDS: {len(suricata_alerts)}")

    return suricata_alerts

def analyze_pcap(file_path):
    print(f"Analyzing PCAP file: {file_path}")

    packets = rdpcap(file_path)

    try:
        for packet in packets:
            process_packet(packet)

    finally:
        flush_remaining_flows()

    process_suricata_results(file_path)
    print_metrics()

def capture_live():
    print(f"Starting live capture on: {INTERFACE_NAME}")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(iface=INTERFACE_NAME, prn=process_packet, store=False)

    except KeyboardInterrupt:
        print("\nStopping live capture...")

    finally:
        flush_remaining_flows()
        print_metrics()


def main():
    parser = argparse.ArgumentParser(description="Hybrid Network Intrusion Detection System")

    parser.add_argument("--live", action="store_true", help="Capture live network traffic")
    parser.add_argument("--pcap", type=str, help="Analyze packets from a PCAP file")

    args = parser.parse_args()

    if args.live:
        capture_live()

    elif args.pcap:
        analyze_pcap(args.pcap)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()