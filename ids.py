from collections import defaultdict

ip_count = defaultdict(int)

def detect_attack(src_ip):
    ip_count[src_ip] += 1

    if ip_count[src_ip] > 20:
        return f"⚠ Possible DoS Attack from {src_ip}"

    return None