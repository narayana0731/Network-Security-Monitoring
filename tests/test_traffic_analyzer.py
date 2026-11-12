
import unittest
from io import StringIO
from contextlib import redirect_stdout

from src.traffic_analyzer import analyze_traffic


class TestTrafficAnalyzer(unittest.TestCase):

    def test_traffic_statistics(self):

        local_ip = "192.0.2.10"

        packets = [
            {
                "source_ip": local_ip,
                "destination_ip": "198.51.100.20",
                "protocol": "TCP",
                "size": 100
            },
            {
                "source_ip": "198.51.100.20",
                "destination_ip": local_ip,
                "protocol": "UDP",
                "size": 200
            },
            {
                "source_ip": "203.0.113.15",
                "destination_ip": "198.51.100.20",
                "protocol": "ICMP",
                "size": 50
            }
        ]

        output = StringIO()

        with redirect_stdout(output):
            analyze_traffic(packets, local_ip)

        result = output.getvalue()

        self.assertIn("Total Packets: 3", result)
        self.assertIn("Total Data: 350 bytes", result)
        self.assertIn("Average Packet Size: 116.67 bytes", result)

        self.assertIn("TCP: 1", result)
        self.assertIn("UDP: 1", result)
        self.assertIn("ICMP: 1", result)

        self.assertIn("Outgoing Packets: 1", result)
        self.assertIn("Incoming Packets: 1", result)
        self.assertIn("Other Packets: 1", result)

        self.assertIn("198.51.100.20", result)

    def test_empty_packet_list(self):

        output = StringIO()

        with redirect_stdout(output):
            analyze_traffic([], "192.0.2.10")

        result = output.getvalue()

        self.assertIn("Total Packets: 0", result)
        self.assertIn("Total Data: 0 bytes", result)
        self.assertIn("Average Packet Size: 0.00 bytes", result)

        self.assertIn("Outgoing Packets: 0", result)
        self.assertIn("Incoming Packets: 0", result)
        self.assertIn("Other Packets: 0", result)


if __name__ == "__main__":
    unittest.main()
