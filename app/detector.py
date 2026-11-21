

from collections import defaultdict, deque
from datetime import datetime
import time


# ==========================================
# IDS CONFIGURATION
# ==========================================

PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW = 10

SYN_THRESHOLD = 30
SYN_WINDOW = 10

ALERT_COOLDOWN = 60

# Common expected service ports
EXPECTED_TCP_PORTS = {22, 53, 80, 443}


# ==========================================
# INTRUSION DETECTION ENGINE
# ==========================================

class IntrusionDetector:

    def __init__(self, local_ip):

        self.local_ip = local_ip

        # Recent destination ports for port scan detection
        self.port_attempts = defaultdict(deque)

        # Recent SYN packets for repeated SYN detection
        self.syn_attempts = defaultdict(deque)

        # Last alert time for duplicate prevention
        self.last_alert = {}

        print("Intrusion Detection Engine initialized")
        print(f"Monitoring local IP: {self.local_ip}")


    # ======================================
    # ALERT GENERATION
    # ======================================

    def generate_alert(
        self,
        rule,
        source_ip,
        destination_ip,
        severity,
        description
    ):

        current_time = time.monotonic()

        alert_key = (
            rule,
            source_ip,
            destination_ip
        )

        # Check cooldown
        previous_alert = self.last_alert.get(alert_key)

        if previous_alert is not None:
            if current_time - previous_alert < ALERT_COOLDOWN:
                return None

        self.last_alert[alert_key] = current_time

        alert = {
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "alert_type": rule,
            "severity": severity,
            "description": description
        }

        print("\n========== IDS ALERT ==========")
        print(f"Time        : {alert['timestamp']}")
        print(f"Alert Type  : {rule}")
        print(f"Severity    : {severity}")
        print(f"Source IP   : {source_ip}")
        print(f"Target IP   : {destination_ip}")
        print(f"Description : {description}")
        print("===============================\n")

        return alert


    # ======================================
    # PORT SCAN DETECTION
    # ======================================

    def detect_port_scan(self, packet_data):

        source_ip = packet_data["src_ip"]
        destination_ip = packet_data["dst_ip"]
        destination_port = packet_data["dst_port"]

        # Consider TCP SYN connection attempts only
        if packet_data["protocol"] != "TCP":
            return None

        if "S" not in packet_data["tcp_flags"]:
            return None

        if "A" in packet_data["tcp_flags"]:
            return None

        if not isinstance(destination_port, int):
            return None

        current_time = time.monotonic()

        key = (source_ip, destination_ip)

        attempts = self.port_attempts[key]

        attempts.append((current_time, destination_port))

        # Remove expired attempts
        while attempts and current_time - attempts[0][0] > PORT_SCAN_WINDOW:
            attempts.popleft()

        distinct_ports = {
            port for timestamp, port in attempts
        }

        if len(distinct_ports) >= PORT_SCAN_THRESHOLD:

            return self.generate_alert(
                rule="PORT_SCAN",
                source_ip=source_ip,
                destination_ip=destination_ip,
                severity="HIGH",
                description=(
                    f"{len(distinct_ports)} distinct destination "
                    f"ports attempted within {PORT_SCAN_WINDOW} seconds"
                )
            )

        return None


    # ======================================
    # REPEATED TCP SYN DETECTION
    # ======================================

    def detect_repeated_syn(self, packet_data):

        source_ip = packet_data["src_ip"]
        destination_ip = packet_data["dst_ip"]

        if packet_data["protocol"] != "TCP":
            return None

        flags = packet_data["tcp_flags"]

        # SYN must be set and ACK must be unset
        if "S" not in flags or "A" in flags:
            return None

        current_time = time.monotonic()

        key = (source_ip, destination_ip)

        attempts = self.syn_attempts[key]

        attempts.append(current_time)

        # Remove expired SYN attempts
        while attempts and current_time - attempts[0] > SYN_WINDOW:
            attempts.popleft()

        if len(attempts) >= SYN_THRESHOLD:

            return self.generate_alert(
                rule="REPEATED_SYN",
                source_ip=source_ip,
                destination_ip=destination_ip,
                severity="HIGH",
                description=(
                    f"{len(attempts)} TCP SYN packets detected "
                    f"within {SYN_WINDOW} seconds"
                )
            )

        return None


    # ======================================
    # UNUSUAL SERVICE ACCESS DETECTION
    # ======================================

    def detect_unusual_service(self, packet_data):

        source_ip = packet_data["src_ip"]
        destination_ip = packet_data["dst_ip"]
        destination_port = packet_data["dst_port"]

        # Initially inspect incoming TCP connection attempts
        if packet_data["protocol"] != "TCP":
            return None

        if destination_ip != self.local_ip:
            return None

        flags = packet_data["tcp_flags"]

        # Only inspect new connection attempts
        if "S" not in flags or "A" in flags:
            return None

        if not isinstance(destination_port, int):
            return None

        if destination_port not in EXPECTED_TCP_PORTS:

            return self.generate_alert(
                rule="UNUSUAL_SERVICE",
                source_ip=source_ip,
                destination_ip=destination_ip,
                severity="MEDIUM",
                description=(
                    f"Incoming connection attempt to unexpected "
                    f"TCP port {destination_port}"
                )
            )

        return None


    # ======================================
    # MAIN DETECTION FUNCTION
    # ======================================

    def analyze_packet(self, packet_data):

        alerts = []

        port_scan_alert = self.detect_port_scan(packet_data)

        if port_scan_alert:
            alerts.append(port_scan_alert)

        syn_alert = self.detect_repeated_syn(packet_data)

        if syn_alert:
            alerts.append(syn_alert)

        service_alert = self.detect_unusual_service(packet_data)

        if service_alert:
            alerts.append(service_alert)

        return alerts
