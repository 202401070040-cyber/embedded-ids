
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
from datetime import datetime
import socket
import signal

from app.database import (
    initialize_database,
    reset_packet_stats,
    increment_packets_examined,
    insert_packet,
    insert_alert,
    update_device,
    log_system_event
)

from app.detector import IntrusionDetector


INTERFACE = "wlo1"


def get_local_ip(interface):
    """Get the IPv4 address assigned to the monitoring interface."""
    import subprocess

    result = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "dev", interface],
        capture_output=True,
        text=True,
        check=True
    )

    for field in result.stdout.split():
        if "/" in field:
            return field.split("/")[0]

    raise RuntimeError(f"No IPv4 address found on {interface}")


LOCAL_IP = get_local_ip(INTERFACE)
detector = IntrusionDetector(local_ip=LOCAL_IP)


def process_packet(packet):

    if IP not in packet:
        return

    packet_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": "OTHER",
        "src_port": "-",
        "dst_port": "-",
        "tcp_flags": "-",
        "packet_length": len(packet)
    }

    if TCP in packet:
        packet_data["protocol"] = "TCP"
        packet_data["src_port"] = packet[TCP].sport
        packet_data["dst_port"] = packet[TCP].dport
        packet_data["tcp_flags"] = str(packet[TCP].flags)

    elif UDP in packet:
        packet_data["protocol"] = "UDP"
        packet_data["src_port"] = packet[UDP].sport
        packet_data["dst_port"] = packet[UDP].dport

    elif ICMP in packet:
        packet_data["protocol"] = "ICMP"

    # Save packet to traffic database
    insert_packet(packet_data)

    print(
        f"{packet_data['protocol']:5} | "
        f"{packet_data['src_ip']} -> "
        f"{packet_data['dst_ip']} | "
        f"Length: {packet_data['packet_length']}"
    )

    # Analyze packet using IDS engine
    alerts = detector.analyze_packet(packet_data)
    increment_packets_examined()

    # Store generated alerts
    for alert in alerts:
        insert_alert(alert)
        print(f"[IDS] Alert saved: {alert['alert_type']}")

    # Extract source and destination MAC addresses
    src_mac = None
    dst_mac = None

    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst

    # Update source device
    update_device(
        ip_address=packet[IP].src,
        mac_address=src_mac
    )

    # Update destination device
    update_device(
        ip_address=packet[IP].dst,
        mac_address=dst_mac
    )


if __name__ == "__main__":

    initialize_database()
    reset_packet_stats()

    # Record IDS startup
    log_system_event(
        "IDS_START",
        "INFO",
        f"Network monitoring started on {INTERFACE}"
    )

    print("\n===================================")
    print(" EMBEDDED LINUX NETWORK IDS")
    print("===================================")
    print(f"Interface : {INTERFACE}")
    print(f"Local IP  : {LOCAL_IP}")
    print("Monitoring started...")
    print("Press CTRL+C to stop.")
    print("===================================\n")

    def handle_sigterm(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, handle_sigterm)

    try:
        sniff(
            iface=INTERFACE,
            prn=process_packet,
            filter="ip",
            store=False,
            chainCC=True
        )

    except KeyboardInterrupt:
        log_system_event(
            "IDS_STOP",
            "INFO",
            "Network monitoring stopped by system or user"
        )
        print("\nIDS monitoring stopped.")

    except Exception as error:
        log_system_event(
            "IDS_ERROR",
            "ERROR",
            str(error)
        )
        print(f"\nCapture error: {error}")
        raise
