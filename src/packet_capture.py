
from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    ICMP,
    get_if_list,
    get_if_addr
)

from traffic_analyzer import analyze_traffic

from threat_detection import (
    detect_port_scans,
    detect_udp_port_scans,
    display_alerts
)

from report_generator import generate_reports


# ==========================================
# 1. DISPLAY AVAILABLE NETWORK INTERFACES
# ==========================================

def show_interfaces():

    print("\nAVAILABLE NETWORK INTERFACES")

    interfaces = get_if_list()

    for number, interface in enumerate(interfaces, start=1):
        print(f"{number}. {interface}")

    return interfaces


# ==========================================
# 2. IDENTIFY PACKET PROTOCOL
# ==========================================

def get_protocol(packet):

    if TCP in packet:
        return "TCP"

    elif UDP in packet:
        return "UDP"

    elif ICMP in packet:
        return "ICMP"

    else:
        return "OTHER"


# ==========================================
# 3. START PACKET CAPTURE
# ==========================================

def start_capture():

    interfaces = show_interfaces()

    if not interfaces:
        print("No network interfaces found.")
        return

    try:

        choice = int(input("\nSelect your Wi-Fi interface number: "))

        if choice < 1 or choice > len(interfaces):
            print("Invalid interface selection.")
            return

    except ValueError:
        print("Please enter a valid number.")
        return

    selected_interface = interfaces[choice - 1]

    # Identify local IPv4 address
    local_ip = get_if_addr(selected_interface)

    if not local_ip or local_ip == "0.0.0.0":

        print("Could not identify the IPv4 address of this interface.")
        print("Please check your interface selection.")
        return

    print(f"\nSelected interface: {selected_interface}")
    print(f"Local IPv4 address: {local_ip}")

    print("\nStarting network packet capture...")
    print("Capturing 10 IPv4 packets. Generate some network activity.")

    captured_packets = []

    # --------------------------------------
    # PROCESS EACH CAPTURED PACKET
    # --------------------------------------

    def process_packet(packet):

        record = {

            "source_ip": packet[IP].src,

            "destination_ip": packet[IP].dst,

            "protocol": get_protocol(packet),

            "size": len(packet),

            "source_port": (
                packet[TCP].sport if TCP in packet
                else packet[UDP].sport if UDP in packet
                else None
            ),

            "destination_port": (
                packet[TCP].dport if TCP in packet
                else packet[UDP].dport if UDP in packet
                else None
            ),

            "tcp_syn": (
                bool(packet[TCP].flags & 0x02)
                if TCP in packet else False
            ),

            "tcp_ack": (
                bool(packet[TCP].flags & 0x10)
                if TCP in packet else False
            )

        }

        captured_packets.append(record)

        packet_number = len(captured_packets)

        print("\n------------------------------")
        print(f"Packet Number: {packet_number}")
        print(f"Source IP: {record['source_ip']}")
        print(f"Destination IP: {record['destination_ip']}")
        print(f"Protocol: {record['protocol']}")
        print(f"Packet Size: {record['size']} bytes")
        print("------------------------------")

    # --------------------------------------
    # CAPTURE AND ANALYZE NETWORK TRAFFIC
    # --------------------------------------

    try:

        sniff(
            iface=selected_interface,
            count=10,
            store=False,
            prn=process_packet,
            lfilter=lambda packet: IP in packet
        )

        print("\nPacket capture completed.")

        if captured_packets:

            # Step 1: Analyze network traffic
            print("\nSending captured packets to traffic analyzer...")

            analyze_traffic(captured_packets, local_ip)

            # Step 2: Detect possible threats
            print("\nChecking for suspicious network activity...")

            # Detect TCP port scans
            tcp_alerts = detect_port_scans(captured_packets)

            # Detect UDP port scans
            udp_alerts = detect_udp_port_scans(captured_packets)

            # Combine both alert lists
            alerts = tcp_alerts + udp_alerts

            # Step 3: Display security alerts
            display_alerts(alerts)

            # Step 4: Generate CSV reports
            print("\nGenerating security reports...")

            generate_reports(captured_packets, alerts, local_ip)

        else:

            print("No IPv4 packets were captured.")

    except PermissionError:

        print("Permission denied. Run VS Code as Administrator.")

    except Exception as error:

        print(f"Capture error: {error}")


# ==========================================
# 4. MAIN PROGRAM
# ==========================================

if __name__ == "__main__":

    start_capture()
