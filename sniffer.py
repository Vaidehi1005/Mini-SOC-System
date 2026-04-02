from scapy.all import sniff, IP

def capture_packets(callback):
    def process(packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            callback(src, dst)

    sniff(prn=process, count=50)