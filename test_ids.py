from sniffer import start_sniffing
from ids import detect_attacks

print("Starting packet capture...")

data = start_sniffing()

print("Captured Data:")
print(data)

alerts = detect_attacks(data)

print("\nDetected Alerts:")
print(alerts)