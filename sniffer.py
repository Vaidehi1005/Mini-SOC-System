from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst

        protocol = "Other"
        port = None

        if TCP in packet:
            protocol = "TCP"
            port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            port = packet[UDP].dport

        return [src, dst, protocol, port]

def start_sniffing():
    packets = sniff(count=20)
    data = []

    for p in packets:
        result = process_packet(p)
        if result:
            data.append(result)

    return data