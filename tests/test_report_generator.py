
import csv
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

import src.report_generator as report_generator


class TestReportGenerator(unittest.TestCase):

    def test_reports_are_generated_correctly(self):

        packets = [
            {
                "source_ip": "192.0.2.10",
                "destination_ip": "192.0.2.20",
                "protocol": "TCP",
                "source_port": 50000,
                "destination_port": 443,
                "size": 100,
                "tcp_syn": True,
                "tcp_ack": False
            }
        ]

        alerts = [
            {
                "type": "Possible TCP Port Scan",
                "source_ip": "192.0.2.10",
                "destination_ip": "192.0.2.20",
                "ports_detected": 10,
                "severity": "Medium"
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:

            with patch.object(
                report_generator,
                "REPORT_DIR",
                Path(temp_dir)
            ):

                report_generator.generate_reports(
                    packets,
                    alerts,
                    local_ip="192.0.2.10"
                )

            packet_files = list(
                Path(temp_dir).glob("packets_*.csv")
            )

            alert_files = list(
                Path(temp_dir).glob("alerts_*.csv")
            )

            self.assertEqual(len(packet_files), 1)
            self.assertEqual(len(alert_files), 1)

            with open(
                packet_files[0],
                "r",
                newline="",
                encoding="utf-8-sig"
            ) as file:

                packet_rows = list(csv.DictReader(file))

            self.assertEqual(len(packet_rows), 1)
            self.assertEqual(
                packet_rows[0]["protocol"],
                "TCP"
            )
            self.assertEqual(
                packet_rows[0]["direction"],
                "Outgoing"
            )

            with open(
                alert_files[0],
                "r",
                newline="",
                encoding="utf-8-sig"
            ) as file:

                alert_rows = list(csv.DictReader(file))

            self.assertEqual(len(alert_rows), 1)
            self.assertEqual(
                alert_rows[0]["type"],
                "Possible TCP Port Scan"
            )
            self.assertEqual(
                alert_rows[0]["severity"],
                "Medium"
            )

    def test_empty_packets_do_not_generate_reports(self):

        with tempfile.TemporaryDirectory() as temp_dir:

            with patch.object(
                report_generator,
                "REPORT_DIR",
                Path(temp_dir)
            ):

                report_generator.generate_reports([], [])

            report_files = list(Path(temp_dir).iterdir())

            self.assertEqual(len(report_files), 0)


if __name__ == "__main__":
    unittest.main()
