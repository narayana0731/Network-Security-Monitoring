
import streamlit as st
import pandas as pd
from pathlib import Path
from datetime import datetime
from streamlit_autorefresh import st_autorefresh


# Configure dashboard
st.set_page_config(
    page_title="Network Security Monitor",
    page_icon="🛡️",
    layout="wide"
)
# Automatically refresh dashboard every 10 seconds
st_autorefresh(
    interval=10_000,
    limit=None,
    key="network_monitor_refresh"
)


# Locate reports folder
PROJECT_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = PROJECT_DIR / "reports"


# Dashboard heading
st.title("🛡️ Network Security Monitoring System")

st.write(
    "Monitor network packets, analyze traffic, "
    "and review security alerts."
)


# Find latest CSV report
def get_latest_report(prefix):

    files = list(REPORT_DIR.glob(f"{prefix}_*.csv"))

    if not files:
        return None

    return max(files, key=lambda file: file.stat().st_mtime)


# Load latest reports
packet_file = get_latest_report("packets")
alert_file = get_latest_report("alerts")


if packet_file is None:

    st.warning(
        "No packet reports found. Run packet_capture.py first."
    )

    st.stop()


packets_df = pd.read_csv(packet_file)

# Display packet report information
st.subheader("Report Information")

col1, col2, col3 = st.columns(3)

col1.metric(
    "Report File",
    packet_file.name
)

col2.metric(
    "Packet Records",
    len(packets_df)
)

last_modified = datetime.fromtimestamp(
    packet_file.stat().st_mtime
).strftime("%d-%m-%Y %H:%M:%S")

col3.metric(
    "Last Updated",
    last_modified
)


if alert_file is not None:
    alerts_df = pd.read_csv(alert_file)
else:
    alerts_df = pd.DataFrame()


# Dashboard metrics
st.subheader("Network Traffic Overview")

total_packets = len(packets_df)

total_bytes = (
    pd.to_numeric(packets_df["size"], errors="coerce")
    .fillna(0)
    .sum()
)

tcp_packets = (
    packets_df["protocol"] == "TCP"
).sum()

udp_packets = (
    packets_df["protocol"] == "UDP"
).sum()

total_alerts = len(alerts_df)


col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Packets", total_packets)

col2.metric("Total Data", f"{total_bytes} bytes")

col3.metric("TCP Packets", tcp_packets)

col4.metric("Security Alerts", total_alerts)


# Protocol statistics
st.subheader("Protocol Distribution")

protocol_counts = packets_df["protocol"].value_counts()

st.bar_chart(protocol_counts)

# Traffic direction
st.subheader("Traffic Direction")

if "direction" in packets_df.columns:

    direction_counts = packets_df["direction"].value_counts()

    st.bar_chart(direction_counts)

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Outgoing",
        int(direction_counts.get("Outgoing", 0))
    )

    col2.metric(
        "Incoming",
        int(direction_counts.get("Incoming", 0))
    )

    col3.metric(
        "Other",
        int(direction_counts.get("Other", 0))
    )

else:

    st.warning(
        "Direction data is missing. "
        "Run packet_capture.py again to generate an updated report."
    )


# Packet table

st.subheader("Captured Packets")

# Get available protocols
available_protocols = sorted(
    packets_df["protocol"].dropna().unique().tolist()
)

# Add All option
protocol_options = ["All"] + available_protocols

# Create protocol filter
selected_protocol = st.selectbox(
    "Filter packets by protocol",
    protocol_options
)

# Filter packets
if selected_protocol == "All":
    filtered_packets = packets_df
else:
    filtered_packets = packets_df[
        packets_df["protocol"] == selected_protocol
    ]

# Display filtered packet count
st.write(f"Showing {len(filtered_packets)} packets")

# Display filtered packet table

# Search packets by IP address
st.subheader("Search Network Traffic")

search_ip = st.text_input(
    "Enter source or destination IP address",
    placeholder="Example: 192.168.1.10"
)

# Apply IP address search
if search_ip:
    filtered_packets = filtered_packets[
        filtered_packets["source_ip"].astype(str).str.contains(
            search_ip, case=False, na=False
        )
        |
        filtered_packets["destination_ip"].astype(str).str.contains(
            search_ip, case=False, na=False
        )
    ]

# Display filtered packet count
st.write(f"Showing {len(filtered_packets)} packets")

# Display packet table
st.dataframe(
    filtered_packets,
    use_container_width=True
)




# Security alerts

st.subheader("Security Alerts")

if not alerts_df.empty:

    # Display alert severity summary
    severity_counts = (
        alerts_df["severity"]
        .fillna("Unknown")
        .value_counts()
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Critical",
        int(severity_counts.get("Critical", 0))
    )

    col2.metric(
        "High",
        int(severity_counts.get("High", 0))
    )

    col3.metric(
        "Medium",
        int(severity_counts.get("Medium", 0))
    )

    col4.metric(
        "Low",
        int(severity_counts.get("Low", 0))
    )

    # Display alerts with severity highlighting
    def highlight_severity(row):

        severity = str(row["severity"]).lower()

        if severity == "critical":
            color = "background-color: #ffcccc"

        elif severity == "high":
            color = "background-color: #ffe0b2"

        elif severity == "medium":
            color = "background-color: #fff3cd"

        elif severity == "low":
            color = "background-color: #d4edda"

        else:
            color = ""

        return [color] * len(row)

    styled_alerts = alerts_df.style.apply(
        highlight_severity,
        axis=1
    )

    st.dataframe(
        styled_alerts,
        use_container_width=True
    )

else:

    st.success("No alerts recorded in the latest report.")



# Download reports
st.subheader("Download Reports")

col1, col2 = st.columns(2)

with col1:

    st.download_button(
        label="Download Packet Report",
        data=packet_file.read_bytes(),
        file_name=packet_file.name,
        mime="text/csv"
    )

with col2:

    if alert_file is not None:

        st.download_button(
            label="Download Alert Report",
            data=alert_file.read_bytes(),
            file_name=alert_file.name,
            mime="text/csv"
        )


st.caption(
    "Educational network monitoring prototype. "
    "Detection results are heuristic, not proof of an attack."
)
