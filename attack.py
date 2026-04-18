from __future__ import annotations

from datetime import datetime, timedelta


def _packet(
    src_ip: str,
    dst_ip: str,
    protocol: str,
    port: int | None,
    timestamp: datetime,
    bytes_sent: int,
    note: str,
) -> dict[str, object]:
    direction = "inbound" if src_ip.startswith(("198.", "203.")) else "internal"
    return {
        "timestamp": timestamp.isoformat(timespec="seconds"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "port": port,
        "bytes": bytes_sent,
        "direction": direction,
        "status": "simulated",
        "note": note,
    }


def available_profiles() -> list[str]:
    return [
        "Port Scan Demo",
        "Brute Force Demo",
        "DoS Spike Demo",
        "Unauthorized Access Demo",
        "Mixed Attack Demo",
    ]


def _background_traffic(start_time: datetime, count: int) -> list[dict[str, object]]:
    packets: list[dict[str, object]] = []
    for index in range(count):
        packets.append(
            _packet(
                src_ip=f"192.168.1.{10 + (index % 8)}",
                dst_ip="172.217.167.78" if index % 2 == 0 else "8.8.8.8",
                protocol="TCP" if index % 2 == 0 else "UDP",
                port=443 if index % 2 == 0 else 53,
                timestamp=start_time + timedelta(seconds=index * 9),
                bytes_sent=350 + (index * 15),
                note="Baseline business traffic",
            )
        )
    return packets


def generate_attack_traffic(profile: str = "Mixed Attack Demo", count: int = 24) -> list[dict[str, object]]:
    start_time = datetime.now() - timedelta(minutes=4)
    packets = _background_traffic(start_time, max(8, count // 3))
    current_time = start_time + timedelta(minutes=1)

    if profile in {"Port Scan Demo", "Mixed Attack Demo"}:
        scan_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 3389]
        for offset, port in enumerate(scan_ports):
            packets.append(
                _packet(
                    src_ip="203.0.113.77",
                    dst_ip="192.168.1.25",
                    protocol="TCP",
                    port=port,
                    timestamp=current_time + timedelta(seconds=offset * 4),
                    bytes_sent=128,
                    note="Reconnaissance sweep across multiple ports",
                )
            )

    if profile in {"Brute Force Demo", "Mixed Attack Demo"}:
        for offset in range(7):
            packets.append(
                _packet(
                    src_ip="198.51.100.24",
                    dst_ip="192.168.1.12",
                    protocol="TCP",
                    port=22,
                    timestamp=current_time + timedelta(seconds=45 + offset * 5),
                    bytes_sent=164,
                    note="Repeated authentication attempts against SSH",
                )
            )

    if profile in {"DoS Spike Demo", "Mixed Attack Demo"}:
        for offset in range(15):
            packets.append(
                _packet(
                    src_ip="198.51.100.99",
                    dst_ip="192.168.1.5",
                    protocol="TCP",
                    port=80,
                    timestamp=current_time + timedelta(seconds=95 + offset * 2),
                    bytes_sent=420,
                    note="Traffic spike targeting the internal web service",
                )
            )

    if profile in {"Unauthorized Access Demo", "Mixed Attack Demo"}:
        for offset, port in enumerate([443, 3389, 3306, 22]):
            packets.append(
                _packet(
                    src_ip="203.0.113.188",
                    dst_ip="192.168.1.50",
                    protocol="TCP",
                    port=port,
                    timestamp=current_time + timedelta(seconds=140 + offset * 6),
                    bytes_sent=220,
                    note="External source reaching private services",
                )
            )

    packets.sort(key=lambda packet: packet["timestamp"])
    return packets
