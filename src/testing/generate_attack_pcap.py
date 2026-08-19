from scapy.all import IP, TCP, ICMP, wrpcap


OUTPUT_PATH = "pcaps/synthetic_attacks.pcap"


def generate_packets():
    packets = []

    # Synthetic Port can
   
    source_ip = "192.0.2.10"
    destination_ip = "192.0.2.20"

    for port in range(20, 32):
        packet = IP(src=source_ip, dst=destination_ip) / TCP(
            sport=40000,
            dport=port,
            flags="S"
        )

        packets.append(packet)

    # Synthetic SYN Flood
    source_ip = "192.0.2.30"
    destination_ip = "192.0.2.40"

    for index in range(60):
        packet = IP(src=source_ip, dst=destination_ip) / TCP(
            sport=41000 + index,
            dport=80,
            flags="S"
        )

        packets.append(packet)

    # Synthetic SSH bruteForce Style Traffic
    source_ip = "192.0.2.50"
    destination_ip = "192.0.2.60"

    for index in range(12):
        packet = IP(src=source_ip, dst=destination_ip) / TCP(
            sport=42000 + index,
            dport=22,
            flags="S"
        )

        packets.append(packet)

    # Synthetic ICMP Flood
    source_ip = "192.0.2.70"
    destination_ip = "192.0.2.80"

    for index in range(60):
        packet = IP(src=source_ip, dst=destination_ip) / ICMP(
            type=8
        )

        packets.append(packet)

    return packets


def main():
    packets = generate_packets()

    wrpcap(OUTPUT_PATH, packets)

    print("--- Synthetic Attack PCAP Created ---")
    print(f"Output: {OUTPUT_PATH}")
    print(f"Total Packets: {len(packets)}")
    print("Port Scan Packets: 12")
    print("SYN Flood Packets: 60")
    print("SSH Brute-Force Style Packets: 12")
    print("ICMP Flood Packets: 60")


if __name__ == "__main__":
    main()