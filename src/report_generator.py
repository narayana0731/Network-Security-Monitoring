
import csv
from datetime import datetime
from pathlib import Path


# Identify the project reports folder
PROJECT_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = PROJECT_DIR / "reports"



def generate_reports(packets, alerts, local_ip=None):

    if not packets:
        print("No packets available. Reports were not generated.")
        return

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    packet_file = REPORT_DIR / f"packets_{timestamp}.csv"
    alert_file = REPORT_DIR / f"alerts_{timestamp}.csv"

    generated_at = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    packet_fields = [
        "report_generated_at",
        "source_ip",
        "destination_ip",
        "protocol",
        "source_port",
        "destination_port",
        "size",
        "tcp_syn",
        "tcp_ack",
        "direction"
    ]

    with open(packet_file, "w", newline="", encoding="utf-8-sig") as file:

        writer = csv.DictWriter(
            file,
            fieldnames=packet_fields,
            extrasaction="ignore"
        )

        writer.writeheader()

        for packet in packets:

            if local_ip and packet["source_ip"] == local_ip:
                direction = "Outgoing"

            elif local_ip and packet["destination_ip"] == local_ip:
                direction = "Incoming"

            else:
                direction = "Other"

            record = {
                **packet,
                "report_generated_at": generated_at,
                "direction": direction
            }

            writer.writerow(record)

    alert_fields = [
    "report_generated_at",
    "type",
    "source_ip",
    "destination_ip",
    "ports_detected",
    "severity"
]

    with open(alert_file, "w", newline="", encoding="utf-8-sig") as file:

        writer = csv.DictWriter(
            file,
            fieldnames=alert_fields,
            extrasaction="ignore"
        )

        writer.writeheader()

        for alert in alerts:

            record = {
                "report_generated_at": generated_at,
                **alert
            }

            writer.writerow(record)

    print("\nREPORT GENERATION COMPLETED")
    print(f"Packet Report: {packet_file}")
    print(f"Alert Report: {alert_file}")

