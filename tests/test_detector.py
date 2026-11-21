

from app.detector import IntrusionDetector
from app.database import insert_alert

detector = IntrusionDetector(local_ip="10.170.84.189")


def make_packet(src, dst, port, flags="S"):
    return {
        "src_ip": src,
        "dst_ip": dst,
        "protocol": "TCP",
        "src_port": 50000,
        "dst_port": port,
        "tcp_flags": flags,
        "packet_length": 60
    }


def test_port_scan():
    print("\nTEST 1: PORT SCAN")

    for port in range(1000, 1015):
        packet = make_packet("192.168.1.50", "10.170.84.189", port)
        alerts = detector.analyze_packet(packet)

        for alert in alerts:
            print("Detected:", alert["alert_type"])
            insert_alert(alert)


def test_repeated_syn():
    print("\nTEST 2: REPEATED SYN")

    for _ in range(30):
        packet = make_packet("192.168.1.60", "10.170.84.189", 80)
        alerts = detector.analyze_packet(packet)

        for alert in alerts:
            print("Detected:", alert["alert_type"])
            insert_alert(alert)


def test_unusual_service():
    print("\nTEST 3: UNUSUAL SERVICE")

    packet = make_packet(
        "192.168.1.70",
        "10.170.84.189",
        4444
    )

    alerts = detector.analyze_packet(packet)

    for alert in alerts:
        print("Detected:", alert["alert_type"])
        insert_alert(alert)


if __name__ == "__main__":
    test_port_scan()
    test_repeated_syn()
    test_unusual_service()

    print("\nAll detection tests executed.")
