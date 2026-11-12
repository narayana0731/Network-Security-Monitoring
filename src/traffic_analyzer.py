
from collections import Counter


def analyze_traffic(packets, local_ip):

    total_packets = len(packets)
    total_bytes = sum(packet["size"] for packet in packets)

    # Count protocols
    protocol_counts = Counter(
        packet["protocol"] for packet in packets
    )

    # Count source and destination IP addresses
    source_counts = Counter(
        packet["source_ip"] for packet in packets
    )

    destination_counts = Counter(
        packet["destination_ip"] for packet in packets
    )

    # Identify packet direction
    outgoing = 0
    incoming = 0
    other = 0

    for packet in packets:

        if packet["source_ip"] == local_ip:
            outgoing += 1

        elif packet["destination_ip"] == local_ip:
            incoming += 1

        else:
            other += 1

    average_size = (
        total_bytes / total_packets if total_packets else 0
    )

    # Display results
    print("\n" + "=" * 50)
    print("NETWORK TRAFFIC ANALYSIS REPORT")
    print("=" * 50)

    print(f"Total Packets: {total_packets}")
    print(f"Total Data: {total_bytes} bytes")
    print(f"Average Packet Size: {average_size:.2f} bytes")

    print("\nPROTOCOL STATISTICS")

    for protocol, count in protocol_counts.most_common():
        print(f"{protocol}: {count}")

    print("\nTRAFFIC DIRECTION")
    print(f"Outgoing Packets: {outgoing}")
    print(f"Incoming Packets: {incoming}")
    print(f"Other Packets: {other}")

    print("\nTOP SOURCE IP ADDRESSES")

    for ip, count in source_counts.most_common(5):
        print(f"{ip}: {count} packets")

    print("\nTOP DESTINATION IP ADDRESSES")

    for ip, count in destination_counts.most_common(5):
        print(f"{ip}: {count} packets")

    print("=" * 50)


if __name__ == "__main__":

    # Synthetic sample data for testing.
    # These are not live network observations.

    local_ip = "192.0.2.10"

    sample_packets = [
        {"source_ip": local_ip, "destination_ip": "198.51.100.20", "protocol": "TCP", "size": 55},
        {"source_ip": "198.51.100.20", "destination_ip": local_ip, "protocol": "TCP", "size": 66},
        {"source_ip": local_ip, "destination_ip": "198.51.100.20", "protocol": "TCP", "size": 55},
        {"source_ip": "198.51.100.20", "destination_ip": local_ip, "protocol": "TCP", "size": 66},
        {"source_ip": local_ip, "destination_ip": "203.0.113.15", "protocol": "UDP", "size": 100},
        {"source_ip": "203.0.113.15", "destination_ip": local_ip, "protocol": "UDP", "size": 120},
        {"source_ip": local_ip, "destination_ip": "198.51.100.30", "protocol": "ICMP", "size": 84},
        {"source_ip": "198.51.100.30", "destination_ip": local_ip, "protocol": "ICMP", "size": 84},
        {"source_ip": local_ip, "destination_ip": "198.51.100.20", "protocol": "TCP", "size": 574},
        {"source_ip": "198.51.100.20", "destination_ip": local_ip, "protocol": "TCP", "size": 54},
    ]

    analyze_traffic(sample_packets, local_ip)
