
from collections import defaultdict


# ==========================================
# 1. TCP PORT SCAN DETECTION
# ==========================================

def detect_port_scans(packets, threshold=10):

    scan_attempts = defaultdict(set)

    for packet in packets:

        if packet["protocol"] != "TCP":
            continue

        # Check for TCP SYN packets without ACK
        if packet.get("tcp_syn") and not packet.get("tcp_ack"):

            source_ip = packet["source_ip"]
            destination_ip = packet["destination_ip"]
            destination_port = packet.get("destination_port")

            if destination_port is not None:

                scan_attempts[
                    (source_ip, destination_ip)
                ].add(destination_port)

    alerts = []

    for (source_ip, destination_ip), ports in scan_attempts.items():

        if len(ports) >= threshold:

            alert = {
                "type": "Possible TCP Port Scan",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "ports_detected": len(ports),
                "severity": "Medium"
            }

            alerts.append(alert)

    return alerts


# ==========================================
# 2. UDP PORT SCAN DETECTION
# ==========================================

def detect_udp_port_scans(packets, threshold=10):

    scan_attempts = defaultdict(set)

    for packet in packets:

        if packet["protocol"] != "UDP":
            continue

        source_ip = packet["source_ip"]
        destination_ip = packet["destination_ip"]
        destination_port = packet.get("destination_port")

        if destination_port is not None:

            scan_attempts[
                (source_ip, destination_ip)
            ].add(destination_port)

    alerts = []

    for (source_ip, destination_ip), ports in scan_attempts.items():

        if len(ports) >= threshold:

            alert = {
                "type": "Possible UDP Port Scan",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "ports_detected": len(ports),
                "severity": "Medium"
            }

            alerts.append(alert)

    return alerts


# ==========================================
# 3. DISPLAY SECURITY ALERTS
# ==========================================

def display_alerts(alerts):

    print("\n" + "=" * 50)
    print("THREAT DETECTION REPORT")
    print("=" * 50)

    if not alerts:

        print("No port-scanning indicators detected.")

    else:

        for alert in alerts:

            print(f"Alert: {alert['type']}")
            print(f"Source IP: {alert['source_ip']}")

            if "destination_ip" in alert:
                print(f"Destination IP: {alert['destination_ip']}")

            print(f"Ports detected: {alert['ports_detected']}")
            print(f"Severity: {alert['severity']}")

            print("-" * 40)

    print("=" * 50)


# ==========================================
# 4. TEST BOTH DETECTION FUNCTIONS
# ==========================================

if __name__ == "__main__":

    # --------------------------------------
    # TCP PORT SCAN TEST
    # --------------------------------------

    print("\nRunning synthetic TCP port-scan test...")

    tcp_sample_packets = []

    for port in range(1, 11):

        tcp_sample_packets.append({

            "source_ip": "198.51.100.25",
            "destination_ip": "203.0.113.10",
            "protocol": "TCP",
            "size": 60,
            "source_port": 50000,
            "destination_port": port,
            "tcp_syn": True,
            "tcp_ack": False

        })

    tcp_alerts = detect_port_scans(tcp_sample_packets)

    display_alerts(tcp_alerts)


    # --------------------------------------
    # UDP PORT SCAN TEST
    # --------------------------------------

    print("\nRunning synthetic UDP port-scan test...")

    udp_sample_packets = []

    for port in range(1, 11):

        udp_sample_packets.append({

            "source_ip": "198.51.100.25",
            "destination_ip": "203.0.113.10",
            "protocol": "UDP",
            "destination_port": port

        })

    udp_alerts = detect_udp_port_scans(udp_sample_packets)

    display_alerts(udp_alerts)
