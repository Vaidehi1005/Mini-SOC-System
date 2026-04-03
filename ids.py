from collections import defaultdict

ip_count = defaultdict(int)
port_scan = defaultdict(set)

def detect_attacks(data):
    alerts = []

    for packet in data:
        src, dst, protocol, port = packet

        # DoS detection
        ip_count[src] += 1
        if ip_count[src] > 15:
            alerts.append(f"🚨 DoS Attack from {src}")

        # Port scan detection
        if port:
            port_scan[src].add(port)
            if len(port_scan[src]) > 8:
                alerts.append(f"🚨 Port Scan from {src}")

    return alerts