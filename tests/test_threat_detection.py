
import unittest

from src.threat_detection import (
    detect_port_scans,
    detect_udp_port_scans
)


class TestThreatDetection(unittest.TestCase):

    # Test 1: TCP port scan should be detected
    def test_tcp_port_scan_detected(self):

        packets = []

        for port in range(1, 11):
            packets.append({
                "source_ip": "198.51.100.25",
                "destination_ip": "203.0.113.10",
                "protocol": "TCP",
                "destination_port": port,
                "tcp_syn": True,
                "tcp_ack": False
            })

        alerts = detect_port_scans(packets)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["type"],
            "Possible TCP Port Scan"
        )

    # Test 2: Normal TCP traffic should not trigger an alert
    def test_tcp_normal_traffic(self):

        packets = [{
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "protocol": "TCP",
            "destination_port": 443,
            "tcp_syn": True,
            "tcp_ack": False
        }]

        alerts = detect_port_scans(packets)

        self.assertEqual(len(alerts), 0)

    # Test 3: UDP port scan should be detected
    def test_udp_port_scan_detected(self):

        packets = []

        for port in range(1, 11):
            packets.append({
                "source_ip": "198.51.100.25",
                "destination_ip": "203.0.113.10",
                "protocol": "UDP",
                "destination_port": port
            })

        alerts = detect_udp_port_scans(packets)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["type"],
            "Possible UDP Port Scan"
        )

    # Test 4: Normal UDP traffic should not trigger an alert
    def test_udp_normal_traffic(self):

        packets = [{
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "protocol": "UDP",
            "destination_port": 53
        }]

        alerts = detect_udp_port_scans(packets)

        self.assertEqual(len(alerts), 0)

    # Test 5: Duplicate TCP ports should not trigger an alert
    def test_tcp_duplicate_ports_not_counted(self):

        packets = []

        for _ in range(15):
            packets.append({
                "source_ip": "198.51.100.25",
                "destination_ip": "203.0.113.10",
                "protocol": "TCP",
                "destination_port": 80,
                "tcp_syn": True,
                "tcp_ack": False
            })

        alerts = detect_port_scans(packets)

        self.assertEqual(len(alerts), 0)

    # Test 6: TCP SYN-ACK packets should not count as SYN scans
    def test_tcp_ack_packets_not_counted(self):

        packets = []

        for port in range(1, 11):
            packets.append({
                "source_ip": "198.51.100.25",
                "destination_ip": "203.0.113.10",
                "protocol": "TCP",
                "destination_port": port,
                "tcp_syn": True,
                "tcp_ack": True
            })

        alerts = detect_port_scans(packets)

        self.assertEqual(len(alerts), 0)

    # Test 7: Duplicate UDP ports should not trigger an alert
    def test_udp_duplicate_ports_not_counted(self):

        packets = []

        for _ in range(15):
            packets.append({
                "source_ip": "198.51.100.25",
                "destination_ip": "203.0.113.10",
                "protocol": "UDP",
                "destination_port": 53
            })

        alerts = detect_udp_port_scans(packets)

        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
