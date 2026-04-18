from attack import generate_attack_traffic
from ids import detect_attacks

traffic = generate_attack_traffic("Mixed Attack Demo", count=36)
alerts = detect_attacks(traffic)

print("Traffic sample size:", len(traffic))
print("Detected alerts:", len(alerts))
for alert in alerts:
    print(f"{alert['id']} | {alert['severity']} | {alert['rule_name']} | {alert['src_ip']}")
